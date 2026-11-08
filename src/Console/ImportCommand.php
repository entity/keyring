<?php

namespace Keyring\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Encryption\DecryptException;
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
 * deletes anything, so drop Fortify's columns yourself when you're happy.
 */
#[AsCommand(name: 'keyring:import')]
class ImportCommand extends Command
{
    protected $signature = 'keyring:import
        {source : Where to import from (only "fortify" for now)}
        {--dry-run : Show what would be imported without writing anything}
        {--unconfirmed : Also import two factor secrets that were never confirmed (Fortify without its "confirm" option)}';

    protected $description = 'Import authenticators from Fortify (TOTP, recovery codes and passkeys)';

    public function handle(): int
    {
        if ($this->argument('source') !== 'fortify') {
            $this->components->error('Only "fortify" can be imported for now.');

            return self::FAILURE;
        }

        $model = config('auth.providers.'.config('auth.guards.'.config('keyring.guard').'.provider').'.model');
        $counts = ['totp' => 0, 'recovery' => 0, 'passkey' => 0, 'skipped' => 0];

        if (Schema::hasColumn((new $model)->getTable(), 'two_factor_secret')) {
            $model::query()->whereNotNull('two_factor_secret')
                ->unless($this->option('unconfirmed'), fn ($query) => $query->whereNotNull('two_factor_confirmed_at'))
                ->chunkById(200, function ($users) use (&$counts) {
                    foreach ($users as $user) {
                        $this->importTwoFactor($user, $counts);
                    }
                });
        }

        if (Schema::hasTable('passkeys')) {
            DB::table('passkeys')->orderBy('id')->chunk(200, function ($passkeys) use ($model, &$counts) {
                foreach ($passkeys as $passkey) {
                    $this->importPasskey($model, $passkey, $counts);
                }
            });
        }

        $this->components->twoColumnDetail('Authenticator apps', (string) $counts['totp']);
        $this->components->twoColumnDetail('Recovery code sets', (string) $counts['recovery']);
        $this->components->twoColumnDetail('Passkeys', (string) $counts['passkey']);
        $this->components->twoColumnDetail('Skipped (already imported or unreadable)', (string) $counts['skipped']);

        if ($this->option('dry-run')) {
            $this->components->warn('Dry run: nothing was written.');
        }

        return self::SUCCESS;
    }

    /**
     * @param  array<string, int>  $counts
     */
    protected function importTwoFactor(Model $user, array &$counts): void
    {
        if ($this->imported($user, 'totp', 'fortify')) {
            $counts['skipped']++;

            return;
        }

        try {
            $secret = decrypt($user->getAttribute('two_factor_secret'));
            $codes = json_decode(decrypt($user->getAttribute('two_factor_recovery_codes') ?? encrypt('[]')), true) ?: [];
        } catch (DecryptException) {
            $counts['skipped']++;

            return;
        }

        $counts['totp']++;
        $counts['recovery'] += $codes === [] ? 0 : 1;

        if ($this->option('dry-run')) {
            return;
        }

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
     */
    protected function importPasskey(string $model, object $passkey, array &$counts): void
    {
        $user = $model::query()->find($passkey->user_id);

        if ($user === null || Keyring::authenticatorModel()::query()->where('credential_id', $passkey->credential_id)->exists()) {
            $counts['skipped']++;

            return;
        }

        $credential = is_string($passkey->credential) ? json_decode($passkey->credential, true) : (array) $passkey->credential;
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
        return Keyring::authenticatorModel()::query()->whereMorphedTo('authenticatable', $user)->where('is_default', true)->exists();
    }

    protected function imported(Model $user, string $factor, string $source): bool
    {
        return Keyring::authenticatorModel()::query()
            ->whereMorphedTo('authenticatable', $user)
            ->where('factor', $factor)
            ->get()
            ->contains(fn (Authenticator $authenticator) => $authenticator->meta('imported_from') === $source);
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
