<?php

namespace Keyring\Console;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Keyring\Concerns\HasKeyring;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Symfony\Component\Console\Attribute\AsCommand;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\multiselect;

#[AsCommand(name: 'keyring:install')]
#[Description('Install Keyring: pick sign-in methods and features, then publish the config, migrations, a provider and your actions')]
#[Signature('keyring:install
        {--factor=* : A sign-in method to add besides the password: totp, passkeys, security-keys or email-codes}
        {--feature=* : A feature to turn on, replacing the defaults (registration and reset-passwords): registration, reset-passwords, email-verification, update-passwords, manage-authenticators, devices, email-changes or security-log}
        {--emails : Register the emails that tell users their password or sign-in methods changed (the default with a second sign-in method)}
        {--no-emails : Register no security emails, only the ones a flow needs}
        {--force : Overwrite files that already exist}')]
class InstallCommand extends Command
{
    /**
     * Sign-in methods besides the password, and the line each adds to the
     * provider's Keyring::factors() call. Recovery codes come with any of
     * them, so losing the only one isn't the end of the account.
     */
    protected const array FACTORS = [
        'totp' => ['Authenticator app', 'Totp::class,'],
        'passkeys' => ['Passkeys', 'WebAuthn::passkeys(),'],
        'security-keys' => ['Security keys, as a second factor', 'WebAuthn::securityKeys(),'],
        'email-codes' => ['Email codes, as a second factor (the weakest option)', 'EmailCode::asSecondFactor(),'],
    ];

    protected const string STUBS = __DIR__.'/../../stubs';

    public function handle(Filesystem $files): int
    {
        $unknown = array_filter([
            '--factor' => [array_diff($this->option('factor'), array_keys(self::FACTORS)), array_keys(self::FACTORS)],
            '--feature' => [array_diff($this->option('feature'), Features::all()), Features::all()],
        ], fn (array $option) => $option[0] !== []);

        foreach ($unknown as $option => [$values, $known]) {
            $this->components->error("Unknown {$option}: ".implode(', ', $values).'. Pick from: '.implode(', ', $known).'.');
        }

        if ($unknown !== []) {
            return self::FAILURE;
        }

        $factors = $this->factors();

        // An existing config is the app's, so there's nothing to ask about it.
        if ($files->exists(config_path('keyring.php')) && ! $this->option('force')) {
            $this->components->warn('Skipped '.config_path('keyring.php').', it already exists.');
            $features = config('keyring.features');
        } else {
            $features = $this->features($factors);
            $files->put(config_path('keyring.php'), $this->config($files, $features));
        }

        // Publishing again would add the migrations twice, under new timestamps.
        if ($files->glob(database_path('migrations/*_create_keyring_authenticators_table.php')) === []) {
            $this->callSilently('vendor:publish', ['--tag' => 'keyring-migrations']);
        }

        // The provider, actions and notifications are your code from here on.
        // Every one is published, so turning a feature on later just works.
        $provider = app_path('Providers/KeyringServiceProvider.php');

        if ($files->exists($provider) && ! $this->option('force')) {
            $this->components->warn("Skipped {$provider}, it already exists.");
        } else {
            $files->ensureDirectoryExists(dirname($provider));
            $files->put($provider, $this->provider($files, $factors, $this->emails($factors)));
        }

        foreach (['Actions/Keyring', 'Notifications/Keyring'] as $directory) {
            foreach ($files->files(self::STUBS.'/app/'.$directory) as $file) {
                $this->write($files, app_path($directory.'/'.$file->getFilename()), $file->getContents());
            }
        }

        ServiceProvider::addProviderToBootstrapFile('App\\Providers\\KeyringServiceProvider');

        $this->components->info('Keyring installed.');
        $this->components->bulletList(array_filter([
            $this->userModelHasKeyring() ? null : 'Add <comment>use Keyring\Concerns\HasKeyring;</comment> to your User model',
            in_array(Features::emailVerification(), $features, true) ? 'Make your User model implement <comment>MustVerifyEmail</comment>' : null,
            $this->migrated() ? null : 'Run <comment>php artisan migrate</comment>',
            'Build the <comment>auth/*</comment> pages Keyring renders, see the "Quick Start" docs',
            'Add features later in <comment>config/keyring.php</comment>, and sign-in methods and emails in your KeyringServiceProvider',
        ]));

        return self::SUCCESS;
    }

    /**
     * @param  list<string>  $factors
     */
    protected function emails(array $factors): bool
    {
        return match (true) {
            $this->option('emails') => true,
            $this->option('no-emails') => false,
            $this->input->isInteractive() => confirm(
                label: 'Email users when their password or sign-in methods change?',
                default: $factors !== [],
                hint: 'Password changed, sign-in method added or removed, recovery code used.',
            ),
            default => $factors !== [],
        };
    }

    protected function userModelHasKeyring(): bool
    {
        $provider = Keyring::provider();

        return $provider instanceof EloquentUserProvider && in_array(HasKeyring::class, class_uses_recursive($provider->getModel()), true);
    }

    protected function migrated(): bool
    {
        return rescue(fn () => Schema::hasTable('keyring_authenticators'), false, report: false);
    }

    /**
     * @return list<string>
     */
    protected function factors(): array
    {
        $chosen = $this->option('factor');

        if ($chosen === [] && $this->input->isInteractive()) {
            $chosen = multiselect(
                label: 'Which sign-in methods besides the password?',
                options: array_map(fn (array $factor) => $factor[0], self::FACTORS),
                hint: 'You can add more later in app/Providers/KeyringServiceProvider.php.',
            );
        }

        return array_values(array_intersect(array_keys(self::FACTORS), $chosen));
    }

    /**
     * @param  list<string>  $factors
     * @return list<string>
     */
    protected function features(array $factors): array
    {
        $chosen = $this->option('feature');

        if ($chosen === []) {
            $chosen = $this->input->isInteractive() ? multiselect(
                label: 'Which features?',
                options: [
                    Features::registration() => 'Registration',
                    Features::resetPasswords() => 'Password resets',
                    Features::emailVerification() => 'Email verification',
                    Features::updatePasswords() => 'Changing the password',
                    Features::manageAuthenticators() => 'Managing sign-in methods (needed to set any up)',
                    Features::devices() => 'Devices: "trust this device" and where you\'re signed in',
                    Features::emailChanges() => 'Email changes, confirmed and undoable',
                    Features::securityLog() => 'Security log and "was this you?" alerts',
                ],
                default: [Features::registration(), Features::resetPasswords(), ...$factors === [] ? [] : [Features::manageAuthenticators()]],
                scroll: 8,
                hint: 'Signing in and out, challenges and step-up are always on.',
            ) : [Features::registration(), Features::resetPasswords()];
        }

        // Users can't set up the sign-in methods without it.
        if ($factors !== [] && ! in_array(Features::manageAuthenticators(), $chosen, true)) {
            $chosen[] = Features::manageAuthenticators();
            $this->components->info('Turned on managing sign-in methods, so users can set up the ones you picked.');
        }

        // Anyone can register someone else's address, so they must prove it
        // before adding a sign-in method that would outlive a password reset.
        if (array_all([Features::registration(), Features::manageAuthenticators()], fn (string $feature) => in_array($feature, $chosen, true))
            && ! in_array(Features::emailVerification(), $chosen, true)) {
            $chosen[] = Features::emailVerification();
            $this->components->info('Turned on email verification, so users prove their address before adding a sign-in method.');
        }

        return array_values(array_intersect(Features::all(), $chosen));
    }

    /**
     * The short config, with the features left out commented, so they're
     * there to turn on later.
     *
     * @param  list<string>  $features
     */
    protected function config(Filesystem $files, array $features): string
    {
        $config = $files->get(self::STUBS.'/config/keyring.php');

        foreach (array_diff(Features::all(), $features) as $feature) {
            $method = Str::camel($feature);
            $config = str_replace("        Features::{$method}(),", "        // Features::{$method}(),", $config);
        }

        return $config;
    }

    /**
     * The provider with only the chosen sign-in methods, and the security
     * notices left commented when they weren't wanted.
     *
     * @param  list<string>  $factors
     */
    protected function provider(Filesystem $files, array $factors, bool $emails): string
    {
        $remove = $factors === [] ? ['RecoveryCodes::class,'] : [];

        foreach (self::FACTORS as $key => [, $line]) {
            if (! in_array($key, $factors, true)) {
                $remove[] = $line;
            }
        }

        $lines = array_filter(
            explode("\n", $files->get(self::STUBS.'/app/Providers/KeyringServiceProvider.php')),
            fn (string $line) => ! str_contains($line, 'Keyring::require(') || $factors !== [],
        );
        $lines = array_filter($lines, fn (string $line) => array_all($remove, fn (string $needle) => ! str_ends_with(trim($line), $needle)));

        $provider = $this->withoutUnusedImports($this->withoutOrphanedComments(implode("\n", $lines)));

        return $emails ? $provider : (string) preg_replace("/^( +)('(?:password_changed|authenticator_added|authenticator_removed|recovery_code_used)' =>)/m", '$1// $2', $provider);
    }

    /**
     * Comments whose code was removed, and the blank line before them.
     */
    protected function withoutOrphanedComments(string $code): string
    {
        return (string) preg_replace('/\n\n(?: +\/\/[^\n]*\n)+(?=\n| *})/', "\n", $code);
    }

    protected function withoutUnusedImports(string $code): string
    {
        return (string) preg_replace_callback('/^use [\w\\\\]+\\\\(\w+);\n/m', fn (array $import) => preg_match_all('/\b'.$import[1].'\b/', $code) > 1 ? $import[0] : '', $code);
    }

    /**
     * Write a file the app owns, leaving anything already there unless --force.
     */
    protected function write(Filesystem $files, string $to, string $contents): void
    {
        if ($files->exists($to) && ! $this->option('force')) {
            $this->components->warn("Skipped {$to}, it already exists.");

            return;
        }

        $files->ensureDirectoryExists(dirname($to));
        $files->put($to, $contents);
    }
}
