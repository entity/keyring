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
        // What a new Laravel app uses, so nothing relies on PHP serialization.
        $app['config']->set('session.serialization', 'json');
    }

    protected function setUp(): void
    {
        parent::setUp();

        // Registered like the published provider does.
        Keyring::createUsersUsing(CreateNewUser::class)
            ->resetUserPasswordsUsing(ResetUserPassword::class)
            ->updateUserPasswordsUsing(UpdateUserPassword::class)
            ->validateEmailChangesUsing(ValidateEmailChange::class);
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
