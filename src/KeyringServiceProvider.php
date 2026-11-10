<?php

namespace Keyring;

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Contracts\Foundation\CachesConfiguration;
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
use Keyring\Exceptions\MissingAction;
use Keyring\Exceptions\UnknownFeature;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Http\Middleware\RequireAssurance;
use Keyring\Http\Middleware\RequireEnrollment;
use Keyring\Http\Middleware\RequireFreshVerification;
use Keyring\Http\Responses as DefaultResponses;
use Keyring\Notifications\SendSecurityNotifications;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Support\Duration;
use Keyring\Support\Url;

class KeyringServiceProvider extends ServiceProvider
{
    /**
     * The app's actions, and how to register each.
     *
     * @var array<class-string, string>
     */
    protected const array ACTIONS = [
        Contracts\CreatesNewUsers::class => 'createUsersUsing',
        Contracts\ResetsUserPasswords::class => 'resetUserPasswordsUsing',
        Contracts\UpdatesUserPasswords::class => 'updateUserPasswordsUsing',
        Contracts\ValidatesEmailChanges::class => 'validateEmailChangesUsing',
    ];

    /**
     * Keyring's own answer for each response contract, until the app swaps
     * one with Keyring::respondWith().
     *
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
        Responses\SignedOutResponse::class => DefaultResponses\SignedOutResponse::class,
        Responses\ConfirmationRequiredResponse::class => DefaultResponses\ConfirmationRequiredResponse::class,
        Responses\EnrollmentRequiredResponse::class => DefaultResponses\EnrollmentRequiredResponse::class,
        Responses\VerifiedResponse::class => DefaultResponses\VerifiedResponse::class,
    ];

    public function register(): void
    {
        $this->mergeConfig();

        // Keyring's services say how long they live themselves, with
        // #[Singleton] or #[Scoped]. These need building a particular way.
        $this->app->bind(RiskLocks::class, fn (Application $app) => new RiskLocks($app->make('cache')->store(config('keyring.risk.store'))));
        $this->app->bind(SessionRegistry::class, fn (Application $app) => $app->make(SessionRegistryManager::class)->driver());
        $this->app->bind(LocatesIps::class, fn (Application $app) => $app->make(config('keyring.devices.locator')));

        // The app registers its own actions; say how when it hasn't.
        foreach (self::ACTIONS as $contract => $method) {
            $this->app->bindIf($contract, fn () => throw MissingAction::for($contract, $method));
        }
    }

    public function boot(): void
    {
        // A misspelt feature would otherwise just be off.
        if (($unknown = array_values(array_diff(config('keyring.features'), Features::all()))) !== []) {
            throw UnknownFeature::in($unknown);
        }

        $this->loadTranslationsFrom(__DIR__.'/../lang', 'keyring');

        $this->registerMiddleware();
        $this->registerListeners();
        $this->configureEmailLinks();
        $this->configureRateLimiting();
        $this->configureRememberMe();

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
        $router = $this->app->make('router');

        $router->aliasMiddleware('keyring', RequireAssurance::class);
        $router->aliasMiddleware('keyring.fresh', RequireFreshVerification::class);
        $router->aliasMiddleware('keyring.session', AuthenticateSession::class);
        $router->aliasMiddleware('keyring.enrolled', RequireEnrollment::class);

        if (config('keyring.sessions.middleware')) {
            $this->app->make(HttpKernel::class)->appendMiddlewareToGroup('web', AuthenticateSession::class);
        }
    }

    /**
     * The app's config over Keyring's defaults, key by key, so an app that
     * copies part of an option (one of the session timeouts) keeps the rest.
     * Laravel's mergeConfigFrom() only goes one level deep. Lists, like the
     * features, are replaced whole.
     */
    protected function mergeConfig(): void
    {
        if ($this->app instanceof CachesConfiguration && $this->app->configurationIsCached()) {
            return;
        }

        $config = $this->app->make('config');
        $config->set('keyring', self::merge(require __DIR__.'/../config/keyring.php', $config->get('keyring', [])));
    }

    /**
     * @param  array<array-key, mixed>  $defaults
     * @param  array<array-key, mixed>  $overrides
     * @return array<array-key, mixed>
     */
    protected static function merge(array $defaults, array $overrides): array
    {
        foreach ($overrides as $key => $value) {
            $default = $defaults[$key] ?? null;

            $defaults[$key] = is_array($value) && is_array($default) && ! array_is_list($value) && ! array_is_list($default)
                ? self::merge($default, $value)
                : $value;
        }

        return $defaults;
    }

    protected function registerListeners(): void
    {
        Event::subscribe(RecordSecurityEvents::class);
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
        if (Features::enabled(Features::emailVerification()) && VerifyEmail::$createUrlCallback === null) {
            VerifyEmail::createUrlUsing(fn (MustVerifyEmail&Model $notifiable) => Url::signed(
                'verification.verify',
                now()->addMinutes((int) config('auth.verification.expire', 60)),
                ['id' => $notifiable->getKey(), 'hash' => sha1($notifiable->getEmailForVerification())],
            ));
        }

        if (Features::enabled(Features::resetPasswords()) && ResetPassword::$createUrlCallback === null) {
            ResetPassword::createUrlUsing(fn (CanResetPassword $notifiable, string $token) => Url::route('password.reset', [
                'token' => $token,
                config('keyring.email') => $notifiable->getEmailForPasswordReset(),
            ]));
        }
    }

    /**
     * The limit on Keyring's form routes (registration, resets, enrollment),
     * and on usernameless login options. Define your own "keyring" or
     * "keyring-login-options" limiter to change them.
     */
    protected function configureRateLimiting(): void
    {
        RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(6)->by($this->app->make(KeyringManager::class)->guard()->id() ?: $request->ip()));

        // The login page asks for these on every load, for passkey autofill,
        // and an office shares one address, so six a minute would be too few.
        // One a second still limits how many challenges a script can make.
        RateLimiter::for('keyring-login-options', fn (Request $request) => Limit::perMinute(60)->by($request->ip()));
    }

    /**
     * "Remember me" can't outlast a session: Laravel's cookie lasts 400 days
     * otherwise. An app that sets its guard's "remember" keeps its own.
     */
    protected function configureRememberMe(): void
    {
        $key = 'auth.guards.'.config('keyring.guard').'.remember';

        if (config($key) === null) {
            config([$key => intdiv(Duration::seconds(config('keyring.sessions.absolute') ?? '30d'), 60)]);
        }
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
            'Features' => implode(', ', config('keyring.features')) ?: 'none',
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
