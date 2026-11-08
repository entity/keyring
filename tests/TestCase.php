<?php

namespace Keyring\Tests;

use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Date;
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
        $app['config']->set('keyring.passwords.uncompromised', false);
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
