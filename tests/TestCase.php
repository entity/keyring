<?php

declare(strict_types=1);

namespace Keyring\Tests;

use App\Actions\Keyring\CreateNewUser;
use App\Actions\Keyring\ResetUserPassword;
use App\Actions\Keyring\UpdateUserPassword;
use App\Actions\Keyring\ValidateEmailChange;
use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Listeners\SendEmailVerificationNotification;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Event;
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

        // Laravel's own listener for new users, which an app's event service
        // provider registers and testbench leaves out.
        Event::listen(Registered::class, SendEmailVerificationNotification::class);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    /**
     * Send these cookies and none of the ones set for earlier requests.
     *
     * @param  array<string, string>  $cookies
     */
    public function withOnlyCookies(array $cookies): static
    {
        $this->defaultCookies = [];

        return $this->withCookies($cookies);
    }

    /**
     * Make requests the way an Inertia page visit would, so pages come back as JSON.
     */
    protected function inertia(): static
    {
        return $this->withHeaders(['X-Inertia' => 'true']);
    }
}
