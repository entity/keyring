<?php

declare(strict_types=1);

namespace Keyring\Console;

use ErrorException;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Keyring\Facades\Keyring;
use Keyring\Factors\RecoveryCodes;
use Keyring\Models\Authenticator;
use Keyring\WebAuthn\Ceremonies;
use ParagonIE\ConstantTime\Base64UrlSafe;
use stdClass;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * Copies Fortify's two factor columns and laravel/passkeys' passkeys table
 * into Keyring's authenticators. Safe to run more than once: it only fills
 * in users with no sign-in methods in Keyring yet, so a later run can't
 * bring back one a user removed. It never deletes Fortify's data, so drop
 * its columns yourself when you're happy.
 *
 * Recovery codes come across as keyed hashes of the codes exactly as
 * Fortify showed them, case included, which is what keeps them above the
 * 112 random bits OWASP ASVS 6.5.2 asks of a code stored that way.
 */
#[AsCommand(name: 'keyring:import')]
#[Description('Import authenticators from Fortify (TOTP, recovery codes and passkeys)')]
#[Signature('keyring:import
        {source : Where to import from (only "fortify" for now)}
        {--dry-run : Show what would be imported without writing anything}
        {--unconfirmed : Also import two factor secrets that were never confirmed, even with the "confirm" option on}
        {--fortify-confirm= : Whether Fortify has its "confirm" option "on" or "off", when its config can not tell}')]
class ImportCommand extends Command
{
    /**
     * Whether each user already had sign-in methods in Keyring when this run
     * first came to them, keyed by morph class and key.
     *
     * @var array<string, bool>
     */
    protected array $inKeyring = [];

    /** @var array{totp: int, recovery: int, passkey: int, already_imported: int} */
    protected array $counts;

    /** @var array{skipped: list<string>, failed: list<string>} */
    protected array $issues;

    public function handle(): int
    {
        $this->inKeyring = [];
        $this->counts = ['totp' => 0, 'recovery' => 0, 'passkey' => 0, 'already_imported' => 0];
        $this->issues = ['skipped' => [], 'failed' => []];

        if ($this->argument('source') !== 'fortify') {
            $this->components->error('Only "fortify" can be imported for now.');

            return self::FAILURE;
        }

        if (! in_array($this->option('fortify-confirm'), [null, 'on', 'off'], true)) {
            $this->components->error('--fortify-confirm must be "on" or "off".');

            return self::FAILURE;
        }

        $provider = Keyring::provider();

        if (! $provider instanceof EloquentUserProvider) {
            $this->components->error('Importing needs an Eloquent user provider.');

            return self::FAILURE;
        }

        $model = $provider->getModel();
        $hasTwoFactor = Schema::hasColumn((new $model)->getTable(), 'two_factor_secret')
            && $model::query()->withoutGlobalScopes()->whereNotNull('two_factor_secret')->exists();
        $hasPasskeys = Schema::hasTable('passkeys') && DB::table('passkeys')->exists();

        // Users with authenticators for a factor that isn't registered can't sign in.
        $missing = array_values(array_filter(
            [...$hasTwoFactor ? ['totp', 'recovery'] : [], ...$hasPasskeys ? ['passkey'] : []],
            fn (string $factor) => ! Keyring::hasFactor($factor),
        ));

        if ($missing !== []) {
            $this->components->error('Register '.implode(', ', $missing).' in Keyring::factors() first. Users with authenticators for a factor Keyring doesn\'t have can\'t sign in.');

            return self::FAILURE;
        }

        if ($hasTwoFactor) {
            // Without global scopes: a soft deleted user can be restored later.
            $model::query()->withoutGlobalScopes()->whereNotNull('two_factor_secret')
                ->chunkById(200, function ($users) {
                    foreach ($users as $user) {
                        $this->importTwoFactor($user);
                    }
                });
        }

        if ($hasPasskeys) {
            DB::table('passkeys')->orderBy('id')->chunk(200, function ($passkeys) use ($model) {
                foreach ($passkeys as $passkey) {
                    $this->importPasskey($model, $passkey);
                }
            });
        }

        $this->components->twoColumnDetail('Authenticator apps', (string) $this->counts['totp']);
        $this->components->twoColumnDetail('Recovery code sets', (string) $this->counts['recovery']);
        $this->components->twoColumnDetail('Passkeys', (string) $this->counts['passkey']);
        $this->components->twoColumnDetail('Already imported', (string) $this->counts['already_imported']);
        $this->components->twoColumnDetail('Skipped', (string) count($this->issues['skipped']));
        $this->components->twoColumnDetail('Failed', (string) count($this->issues['failed']));

        foreach ($this->issues['skipped'] as $issue) {
            $this->warn("Skipped {$issue}");
        }

        foreach ($this->issues['failed'] as $issue) {
            $this->error("Failed {$issue}");
        }

        if ($this->option('dry-run')) {
            $this->components->warn('Dry run: nothing was written.');
        }

        if ($this->issues['failed'] !== []) {
            $this->components->error('Some factors could not be imported. Sort them out before removing Fortify.');

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    protected function importTwoFactor(Model $user): void
    {
        // A stand-in is an import that failed before, still to be finished.
        if (! $this->unusable($user)->exists() && $this->alreadyInKeyring($user, 'fortify')) {
            return;
        }

        if ($user->getAttribute('two_factor_confirmed_at') === null && ! $this->option('unconfirmed')) {
            $confirms = $this->fortifyConfirms();

            if ($confirms === null) {
                $this->issues['failed'][] = "user {$user->getKey()}: its secret was never confirmed and Fortify's confirm option can't be read. Pass --fortify-confirm=on or --fortify-confirm=off.";

                return;
            }

            if ($confirms) {
                $this->issues['skipped'][] = "user {$user->getKey()}: its secret was never confirmed, so Fortify wasn't enforcing it. Pass --unconfirmed to import it anyway.";

                return;
            }
        }

        $encrypter = $this->fortifyEncrypter();

        try {
            $secret = $encrypter->decrypt($user->getAttribute('two_factor_secret'));
            $encrypted = $user->getAttribute('two_factor_recovery_codes');
            $codes = $encrypted === null ? [] : json_decode((string) $encrypter->decrypt($encrypted), true);
        } catch (DecryptException|ErrorException) {
            $this->failTwoFactor($user, "its two factor secret or recovery codes can't be decrypted");

            return;
        }

        if (! is_string($secret) || $secret === '' || ! is_array($codes) || ! array_is_list($codes) || ! array_all($codes, fn ($code) => is_string($code))) {
            $this->failTwoFactor($user, 'its two factor secret or recovery codes are in an unexpected format');

            return;
        }

        // Fortify's codes are long enough to keep as keyed hashes (20 letters
        // and digits, 119 random bits). Anything else in that column would be
        // too easy to guess stored that way, so the set stays behind and the
        // user makes a new one.
        if (! array_all($codes, app(RecoveryCodes::class)->accepts(...))) {
            $this->issues['skipped'][] = "the recovery codes of user {$user->getKey()}: they aren't the 20 letters and digits Fortify makes, and shorter codes are too easy to guess to store as Keyring does. Their authenticator app is imported, and they can make new codes";
            $codes = [];
        }

        $this->counts['totp']++;
        $this->counts['recovery'] += $codes === [] ? 0 : 1;

        if ($this->option('dry-run')) {
            return;
        }

        // Together or not at all: a half import would be skipped next time.
        DB::transaction(function () use ($user, $secret, $codes) {
            $this->unusable($user)->delete();
            $this->createTwoFactor($user, $secret, $codes);
        });
    }

    /**
     * Whether Fortify's "confirm" option is on, null when that can't be told
     * (Fortify::confirmsTwoFactorAuthentication() needs the feature enabled).
     */
    protected function fortifyConfirms(): ?bool
    {
        if ($this->option('fortify-confirm') !== null) {
            return $this->option('fortify-confirm') === 'on';
        }

        $features = config('fortify.features');

        return is_array($features) && in_array('two-factor-authentication', $features, true)
            ? config('fortify-options.two-factor-authentication.confirm') === true
            : null;
    }

    /**
     * Fortify's own resolution: its encrypter, then Eloquent's, then Crypt.
     */
    protected function fortifyEncrypter(): Encrypter
    {
        $fortify = 'Laravel\Fortify\Fortify';

        return class_exists($fortify) ? $fortify::currentEncrypter() : Model::currentEncrypter();
    }

    /**
     * A confirmed authenticator without a secret can never be verified, so
     * the user stays challenged instead of falling back to a password alone.
     * A later import that can read the secret replaces it.
     */
    protected function failTwoFactor(Model $user, string $reason): void
    {
        $this->issues['failed'][] = "user {$user->getKey()}: {$reason}";

        if ($this->option('dry-run') || $this->unusable($user)->exists()) {
            return;
        }

        $this->create($user, [
            'factor' => 'totp',
            'name' => __('Authenticator app'),
            'confirmed_at' => now(),
            'meta' => ['import_failed_from' => 'fortify'],
        ]);
    }

    /**
     * @return Builder<Authenticator>
     */
    protected function unusable(Model $user): Builder
    {
        return Keyring::authenticatorModel()::query()->ownedBy($user)->where('meta->import_failed_from', 'fortify');
    }

    /**
     * @param  list<string>  $codes
     */
    protected function createTwoFactor(Model $user, string $secret, array $codes): void
    {
        $this->create($user, [
            'factor' => 'totp',
            'name' => __('Authenticator app'),
            'secret' => $secret,
            'is_default' => true,
            'confirmed_at' => $user->getAttribute('two_factor_confirmed_at') ?? now(),
            'meta' => ['imported_from' => 'fortify'],
        ]);

        if ($codes !== []) {
            $this->create($user, [
                'factor' => 'recovery',
                'name' => __('Recovery codes'),
                'secret' => app(RecoveryCodes::class)->secretFor($codes),
                'confirmed_at' => now(),
                'meta' => ['imported_from' => 'fortify'],
            ]);
        }
    }

    /**
     * laravel/passkeys stores the same CredentialRecord format Keyring uses.
     *
     * @param  class-string<Model>  $model
     */
    protected function importPasskey(string $model, stdClass $passkey): void
    {
        if (Keyring::authenticatorModel()::query()->where('credential_id', $passkey->credential_id)->exists()) {
            $this->counts['already_imported']++;

            return;
        }

        $user = $model::query()->withoutGlobalScopes()->whereKey($passkey->user_id)->first();

        if ($user === null) {
            $this->issues['failed'][] = "passkey {$passkey->id} of user {$passkey->user_id}: that user doesn't exist";

            return;
        }

        if ($this->alreadyInKeyring($user, 'laravel/passkeys', "passkey {$passkey->id} of ")) {
            return;
        }

        $credential = is_string($passkey->credential) ? json_decode($passkey->credential, true) : (array) $passkey->credential;

        // Anything else would be stored, then fail every time it's read.
        if (! is_array($credential) || ! $this->isCredentialId($passkey->credential_id) || app(Ceremonies::class)->record((string) json_encode($credential)) === null) {
            $this->issues['failed'][] = "passkey {$passkey->id} of user {$passkey->user_id}: its credential is in an unexpected format";

            return;
        }

        $this->counts['passkey']++;

        if ($this->option('dry-run')) {
            return;
        }

        $this->create($user, [
            'factor' => 'passkey',
            'name' => $passkey->name,
            'credential_id' => $passkey->credential_id,
            'public_key' => json_encode($credential),
            'sign_count' => (int) ($credential['counter'] ?? 0),
            'aaguid' => $credential['aaguid'] ?? null,
            'transports' => $credential['transports'] ?? [],
            'confirmed_at' => $passkey->created_at ?? now(),
            'last_used_at' => $passkey->last_used_at ?? null,
            'meta' => ['imported_from' => 'laravel/passkeys', 'user_verified' => (bool) ($credential['uvInitialized'] ?? true)],
        ]);
    }

    /**
     * Whether the user had sign-in methods in Keyring before this run, other
     * than a failed import's stand-in. Once they have, what they have is
     * theirs: importing again would bring back a factor they removed, or a
     * second set of recovery codes, including ones already spent.
     *
     * Something left out is said so. A source imported before is counted as
     * already imported, while one a past run brought nothing from is listed
     * as skipped: it failed then, or the user removed it since, and nothing
     * here can tell which.
     */
    protected function alreadyInKeyring(Model $user, string $source, string $what = ''): bool
    {
        $authenticators = fn () => Keyring::authenticatorModel()::query()->ownedBy($user)->whereNull('meta->import_failed_from');

        if (! ($this->inKeyring[$user->getMorphClass().':'.$user->getKey()] ??= $authenticators()->exists())) {
            return false;
        }

        $reason = match (true) {
            $authenticators()->where('meta->imported_from', $source)->exists() => null,
            $authenticators()->whereNotNull('meta->imported_from')->exists() => 'an earlier import left this out, or they removed it since, so it stays out. Add it again in the app if it should be there',
            default => "they already have sign-in methods in Keyring, so Fortify's are left out",
        };

        if ($reason === null) {
            $this->counts['already_imported']++;
        } elseif (! in_array($issue = "{$what}user {$user->getKey()}: {$reason}", $this->issues['skipped'], true)) {
            $this->issues['skipped'][] = $issue;
        }

        return true;
    }

    /**
     * Whether the ID is unpadded base64url, as Keyring keeps and looks up
     * credential IDs.
     */
    protected function isCredentialId(mixed $id): bool
    {
        return is_string($id) && $id !== '' && rescue(fn () => Base64UrlSafe::encodeUnpadded(Base64UrlSafe::decodeNoPadding($id)) === $id, false, report: false);
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    protected function create(Model $user, array $attributes): void
    {
        new (Keyring::authenticatorModel())($attributes)->authenticatable()->associate($user)->save();
    }
}
