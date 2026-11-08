<?php

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
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * Copies Fortify's two factor columns and laravel/passkeys' passkeys table
 * into Keyring's authenticators. Safe to run more than once; it never
 * deletes Fortify's data, so drop its columns yourself when you're happy.
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
    public function handle(): int
    {
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
        $counts = ['totp' => 0, 'recovery' => 0, 'passkey' => 0, 'already_imported' => 0];
        $issues = ['skipped' => [], 'failed' => []];

        if (Schema::hasColumn((new $model)->getTable(), 'two_factor_secret')) {
            // Without global scopes: a soft deleted user can be restored later.
            $model::query()->withoutGlobalScopes()->whereNotNull('two_factor_secret')
                ->chunkById(200, function ($users) use (&$counts, &$issues) {
                    foreach ($users as $user) {
                        $this->importTwoFactor($user, $counts, $issues);
                    }
                });
        }

        if (Schema::hasTable('passkeys')) {
            DB::table('passkeys')->orderBy('id')->chunk(200, function ($passkeys) use ($model, &$counts, &$issues) {
                foreach ($passkeys as $passkey) {
                    $this->importPasskey($model, $passkey, $counts, $issues);
                }
            });
        }

        $this->components->twoColumnDetail('Authenticator apps', (string) $counts['totp']);
        $this->components->twoColumnDetail('Recovery code sets', (string) $counts['recovery']);
        $this->components->twoColumnDetail('Passkeys', (string) $counts['passkey']);
        $this->components->twoColumnDetail('Already imported', (string) $counts['already_imported']);
        $this->components->twoColumnDetail('Skipped', (string) count($issues['skipped']));
        $this->components->twoColumnDetail('Failed', (string) count($issues['failed']));

        foreach ($issues['skipped'] as $issue) {
            $this->warn("Skipped {$issue}");
        }

        foreach ($issues['failed'] as $issue) {
            $this->error("Failed {$issue}");
        }

        if ($this->option('dry-run')) {
            $this->components->warn('Dry run: nothing was written.');
        }

        if ($issues['failed'] !== []) {
            $this->components->error('Some factors could not be imported. Sort them out before removing Fortify.');

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    /**
     * @param  array<string, int>  $counts
     * @param  array{skipped: list<string>, failed: list<string>}  $issues
     */
    protected function importTwoFactor(Model $user, array &$counts, array &$issues): void
    {
        if ($this->imported($user, 'totp', 'fortify')) {
            $counts['already_imported']++;

            return;
        }

        if ($user->getAttribute('two_factor_confirmed_at') === null && ! $this->option('unconfirmed')) {
            $confirms = $this->fortifyConfirms();

            if ($confirms === null) {
                $issues['failed'][] = "user {$user->getKey()}: its secret was never confirmed and Fortify's confirm option can't be read. Pass --fortify-confirm=on or --fortify-confirm=off.";

                return;
            }

            if ($confirms) {
                $issues['skipped'][] = "user {$user->getKey()}: its secret was never confirmed, so Fortify wasn't enforcing it. Pass --unconfirmed to import it anyway.";

                return;
            }
        }

        $encrypter = $this->fortifyEncrypter();

        try {
            $secret = $encrypter->decrypt($user->getAttribute('two_factor_secret'));
            $encrypted = $user->getAttribute('two_factor_recovery_codes');
            $codes = $encrypted === null ? [] : json_decode((string) $encrypter->decrypt($encrypted), true);
        } catch (DecryptException|ErrorException) {
            $this->failTwoFactor($user, $issues, "its two factor secret or recovery codes can't be decrypted");

            return;
        }

        if (! is_string($secret) || $secret === '' || ! is_array($codes) || ! array_is_list($codes) || ! array_all($codes, fn ($code) => is_string($code))) {
            $this->failTwoFactor($user, $issues, 'its two factor secret or recovery codes are in an unexpected format');

            return;
        }

        $counts['totp']++;
        $counts['recovery'] += $codes === [] ? 0 : 1;

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
     *
     * @param  array{skipped: list<string>, failed: list<string>}  $issues
     */
    protected function failTwoFactor(Model $user, array &$issues, string $reason): void
    {
        $issues['failed'][] = "user {$user->getKey()}: {$reason}";

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
            'is_default' => ! $this->hasDefault($user),
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
     * @param  array<string, int>  $counts
     * @param  array{skipped: list<string>, failed: list<string>}  $issues
     */
    protected function importPasskey(string $model, object $passkey, array &$counts, array &$issues): void
    {
        if (Keyring::authenticatorModel()::query()->where('credential_id', $passkey->credential_id)->exists()) {
            $counts['already_imported']++;

            return;
        }

        $user = $model::query()->withoutGlobalScopes()->find($passkey->user_id);

        if ($user === null) {
            $issues['failed'][] = "passkey {$passkey->id} of user {$passkey->user_id}: that user doesn't exist";

            return;
        }

        $credential = is_string($passkey->credential) ? json_decode($passkey->credential, true) : (array) $passkey->credential;

        if (! is_array($credential) || $credential === []) {
            $issues['failed'][] = "passkey {$passkey->id} of user {$passkey->user_id}: its credential is in an unexpected format";

            return;
        }

        $counts['passkey']++;

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

    protected function hasDefault(Model $user): bool
    {
        return Keyring::authenticatorModel()::query()->ownedBy($user)->where('is_default', true)->exists();
    }

    protected function imported(Model $user, string $factor, string $source): bool
    {
        return Keyring::authenticatorModel()::query()
            ->ownedBy($user)
            ->where('factor', $factor)
            ->where('meta->imported_from', $source)
            ->exists();
    }

    /**
     * @param  array<string, mixed>  $attributes
     */
    protected function create(Model $user, array $attributes): void
    {
        $model = Keyring::authenticatorModel();
        $authenticator = new $model($attributes);
        $authenticator->authenticatable()->associate($user);
        $authenticator->save();
    }
}
