<?php

namespace Keyring;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Console\AboutCommand;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Keyring\Activity\DispatchLaravelEvents;
use Keyring\Activity\RecordSecurityEvents;
use Keyring\Contracts\LocatesIps;
use Keyring\Contracts\Responses;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enrollment\EnrollmentStore;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Http\Middleware\RequireAssurance;
use Keyring\Http\Middleware\RequireFreshVerification;
use Keyring\Http\Responses as DefaultResponses;
use Keyring\Login\AttemptStore;
use Keyring\Notifications\SendSecurityNotifications;
use Keyring\Risk\RiskEngine;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Support\Features;
use Keyring\Support\Url;
use Keyring\WebAuthn\Ceremonies;

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
        Responses\RegisterResponse::class => DefaultResponses\RegisterResponse::class,
        Responses\StatusResponse::class => DefaultResponses\StatusResponse::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/keyring.php', 'keyring');

        $this->app->singleton(KeyringManager::class);
        $this->app->singleton(Ceremonies::class);
        $this->app->singleton(SessionRegistryManager::class);
        $this->app->singleton(RiskEngine::class);
        $this->app->bind(RiskLocks::class, fn (Application $app) => new RiskLocks($app['cache']->store(config('keyring.risk.store'))));
        $this->app->bind(SessionRegistry::class, fn (Application $app) => $app->make(SessionRegistryManager::class)->driver());
        $this->app->bind(LocatesIps::class, fn (Application $app) => $app->make(config('keyring.devices.locator')));

        // Per request, since they wrap the current session.
        $this->app->scoped(AttemptStore::class);
        $this->app->scoped(EnrollmentStore::class);
        $this->app->scoped(SessionAssurance::class);
    }

    public function boot(): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'keyring');

        $this->registerMiddleware();
        $this->registerListeners();
        $this->configureEmailLinks();
        $this->configureRateLimiting();

        if (config('keyring.routes')) {
            $this->registerRoutes();
        }

        if ($this->app->runningInConsole()) {
            $this->registerPublishing();
            $this->registerAboutSection();
        }
    }

    protected function registerMiddleware(): void
    {
        $router = $this->app['router'];

        $router->aliasMiddleware('keyring', RequireAssurance::class);
        $router->aliasMiddleware('keyring.fresh', RequireFreshVerification::class);
        $router->aliasMiddleware('keyring.session', AuthenticateSession::class);

        if (config('keyring.sessions.middleware')) {
            $this->app->make(HttpKernel::class)->appendMiddlewareToGroup('web', AuthenticateSession::class);
        }
    }

    protected function registerListeners(): void
    {
        if (config('keyring.events.enabled')) {
            Event::subscribe(RecordSecurityEvents::class);
        }

        Event::subscribe(SendSecurityNotifications::class);
        Event::subscribe(DispatchLaravelEvents::class);
    }

    /**
     * Laravel's verification and reset emails, with links built from APP_URL
     * rather than the request's Host header. Apps that set their own URL
     * callbacks keep them.
     */
    protected function configureEmailLinks(): void
    {
        if (Features::enabled('email_verification') && VerifyEmail::$createUrlCallback === null) {
            VerifyEmail::createUrlUsing(fn (MustVerifyEmail&Model $notifiable) => Url::signed(
                'verification.verify',
                now()->addMinutes((int) config('auth.verification.expire', 60)),
                ['id' => $notifiable->getKey(), 'hash' => sha1($notifiable->getEmailForVerification())],
            ));
        }

        if (Features::enabled('password_reset') && ResetPassword::$createUrlCallback === null) {
            ResetPassword::createUrlUsing(fn (CanResetPassword $notifiable, string $token) => Url::route('password.reset', [
                'token' => $token,
                'email' => $notifiable->getEmailForPasswordReset(),
            ]));
        }
    }

    /**
     * The limit on Keyring's form routes (registration, resets, enrollment).
     * Define your own "keyring" limiter to change it.
     */
    protected function configureRateLimiting(): void
    {
        RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(6)->by($this->app->make(KeyringManager::class)->guard()->id() ?: $request->ip()));
    }

    protected function registerRoutes(): void
    {
        if ($this->app->routesAreCached()) {
            return;
        }

        Route::prefix(config('keyring.prefix'))
            ->domain(config('keyring.domain'))
            ->group(fn () => $this->app->make(KeyringManager::class)->routes());
    }

    /**
     * Keyring's setup in `php artisan about`.
     */
    protected function registerAboutSection(): void
    {
        if (! class_exists(AboutCommand::class)) {
            return;
        }

        AboutCommand::add('Keyring', fn () => [
            'Guard' => config('keyring.guard'),
            'Factors' => $this->app->make(KeyringManager::class)->registered()->keys()->implode(', '),
            'Features' => collect(config('keyring.features'))->filter()->keys()->implode(', ') ?: 'none',
            'Session registry' => config('keyring.sessions.driver'),
        ]);
    }

    protected function registerPublishing(): void
    {
        $this->commands([Console\InstallCommand::class, Console\ImportCommand::class, Console\PruneCommand::class]);

        $this->publishes([__DIR__.'/../config/keyring.php' => config_path('keyring.php')], 'keyring-config');
        $this->publishesMigrations([__DIR__.'/../database/migrations' => database_path('migrations')], 'keyring-migrations');
        $this->publishes([__DIR__.'/../lang' => $this->app->langPath('vendor/keyring')], 'keyring-lang');
    }
}
