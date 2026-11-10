<?php

namespace Keyring\Tests;

use App\Actions\Keyring\CreateNewUser;
use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Date;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\KeyringServiceProvider;
use Keyring\Testing\InteractsWithKeyring;
use Keyring\Tests\Fixtures\User;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use InteractsWithKeyring, RefreshDatabase;

    protected function getPackageProviders($app): array
    {
        return [
            KeyringServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        // Like Laravel's starter kits, so nothing relies on mutable dates.
        Date::use(CarbonImmutable::class);

        $app['config']->set('database.default', getenv('DB_CONNECTION') ?: 'testing');
        $app['config']->set('auth.providers.users.model', User::class);

        // Every feature, so the suite covers them all. Tests of a feature
        // being off turn it off themselves.
        $app['config']->set('keyring.features', Features::all());
        // What a new Laravel app uses, so nothing relies on PHP serialization.
        $app['config']->set('session.serialization', 'json');
    }

    protected function setUp(): void
    {
        parent::setUp();

        // A full install: the usual sign-in methods, and the actions
        // registered like the published provider does.
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class]);
        Keyring::createUsersUsing(CreateNewUser::class)
            ->resetUserPasswordsUsing(ResetUserPassword::class)
            ->updateUserPasswordsUsing(UpdateUserPassword::class)
            ->validateEmailChangesUsing(ValidateEmailChange::class);

        // And the emails it registers: the ones a flow needs, and the four
        // security notices keyring:install turns on.
        sendNotifications([
            'verification_code', 'confirm_email_change', 'email_change_notice', 'email_address_in_use',
            'password_changed', 'authenticator_added', 'authenticator_removed', 'recovery_code_used',
        ]);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    /**
     * Make requests the way an Inertia page visit would, so pages come back as JSON.
     */
    protected function inertia(): static
    {
        return $this->withHeaders(['X-Inertia' => 'true']);
    }
}
