<?php

namespace Keyring;

use Illuminate\Support\ServiceProvider;

class KeyringServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/keyring.php', 'keyring');

        $this->app->singleton(KeyringManager::class);
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/keyring.php' => config_path('keyring.php'),
            ], 'keyring-config');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'keyring-migrations');
        }
    }
}
