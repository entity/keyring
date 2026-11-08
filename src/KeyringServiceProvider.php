<?php

namespace Keyring;

use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Keyring\Contracts\Responses;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Http\Middleware\RequireAssurance;
use Keyring\Http\Middleware\RequireFreshVerification;
use Keyring\Http\Responses as DefaultResponses;
use Keyring\Login\AttemptStore;
use Keyring\Session\SessionAssurance;

class KeyringServiceProvider extends ServiceProvider
{
    /**
     * @var array<class-string, class-string>
     */
    public array $bindings = [
        Responses\AuthenticatedResponse::class => DefaultResponses\AuthenticatedResponse::class,
        Responses\ChallengeResponse::class => DefaultResponses\ChallengeResponse::class,
        Responses\FailedResponse::class => DefaultResponses\FailedResponse::class,
        Responses\LockoutResponse::class => DefaultResponses\LockoutResponse::class,
        Responses\LogoutResponse::class => DefaultResponses\LogoutResponse::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/keyring.php', 'keyring');

        $this->app->singleton(KeyringManager::class);

        $this->app->scoped(AttemptStore::class, fn (Application $app) => new AttemptStore($app['session.store']));
        $this->app->scoped(EnrollmentStore::class, fn (Application $app) => new EnrollmentStore($app['session.store']));
        $this->app->scoped(SessionAssurance::class, fn (Application $app) => new SessionAssurance($app['session.store']));
    }

    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'keyring');

        $router = $this->app['router'];
        $router->aliasMiddleware('keyring', RequireAssurance::class);
        $router->aliasMiddleware('keyring.fresh', RequireFreshVerification::class);

        if (config('keyring.routes')) {
            $this->registerRoutes();
        }

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/keyring.php' => config_path('keyring.php'),
            ], 'keyring-config');

            $this->publishesMigrations([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], 'keyring-migrations');

            $this->publishes([
                __DIR__.'/../lang' => $this->app->langPath('vendor/keyring'),
            ], 'keyring-lang');
        }
    }

    protected function registerRoutes(): void
    {
        Route::group([
            'prefix' => config('keyring.prefix'),
            'domain' => config('keyring.domain'),
            'middleware' => config('keyring.middleware'),
        ], function () {
            $this->loadRoutesFrom(__DIR__.'/../routes/keyring.php');
        });
    }
}
