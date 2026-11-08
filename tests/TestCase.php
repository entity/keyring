<?php

namespace Keyring\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Timebox;
use Keyring\KeyringServiceProvider;
use Keyring\Testing\InstantTimebox;
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
        $app['config']->set('database.default', getenv('DB_CONNECTION') ?: 'testing');
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('keyring.passwords.uncompromised', false);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->app->bind(Timebox::class, InstantTimebox::class);
    }

    /**
     * Make requests the way an Inertia page visit would, so pages come back as JSON.
     */
    protected function inertia(): static
    {
        return $this->withHeaders(['X-Inertia' => 'true']);
    }
}
