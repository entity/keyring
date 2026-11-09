<?php

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Route;
use Inertia\ServiceProvider;
use Keyring\Exceptions\MissingPage;
use Keyring\Exceptions\MissingTrait;
use Keyring\Exceptions\UnknownFeature;
use Keyring\Facades\Keyring;
use Keyring\Factors\Totp;
use Keyring\Features;
use Keyring\KeyringServiceProvider;

it('lets apps register the routes themselves, e.g. under a prefix', function () {
    Route::prefix('account')->group(fn () => Keyring::routes());

    $this->inertia()->get('/account/login')->assertOk()->assertJsonPath('component', 'auth/login');
});

it('takes the session lock on routes that spend session state', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->locksFor())->toBeGreaterThan(0);
})->with([
    'login.store', 'keyring.login.factor', 'keyring.login.challenge', 'keyring.login.verify', 'keyring.login.send',
    'keyring.confirm.challenge', 'keyring.confirm.verify', 'keyring.confirm.send', 'keyring.authenticators.confirm',
]);

it('limits routes that check a secret outside the sign in limits', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->gatherMiddleware())->toContain('throttle:keyring');
})->with([
    'register.store', 'password.email', 'password.update', 'user-password.update',
    'keyring.authenticators.confirm', 'keyring.authenticators.destroy', 'keyring.email.store', 'keyring.email.revert.store',
]);

it('registers custom factors with extend, under the key they report', function () {
    Keyring::extend('totp', fn ($app) => $app->make(Totp::class));
    expect(Keyring::factor('totp'))->toBeInstanceOf(Totp::class);

    Keyring::extend('sms', fn ($app) => $app->make(Totp::class));
    expect(fn () => Keyring::registered())->toThrow(InvalidArgumentException::class, 'Factor registered as [sms] reports the key [totp].');
});

it('says which blade view a page needs and what it receives', function () {
    expect(MissingPage::forBlade('login', 'auth.login', ['canResetPassword', 'status'])->getMessage())
        ->toContain('resources/views/auth/login.blade.php')
        ->toContain('$canResetPassword, $status')
        ->toContain("Keyring::page('login', ...)");
});

it('says which inertia component a page needs when inertia checks that pages exist', function () {
    $this->app->register(ServiceProvider::class);
    config(['inertia.pages.ensure_pages_exist' => true]);

    $this->withoutExceptionHandling()->inertia()->get('/login');
})->throws(MissingPage::class, 'Create [auth/login] in your pages directory (it receives canResetPassword');

it('says which trait a user model is missing', function () {
    Keyring::for(new class extends User {});
})->throws(MissingTrait::class, 'needs the [Keyring\\Concerns\\HasKeyring] trait');

it('merges the app\'s config over its defaults key by key, but replaces lists whole', function () {
    config(['keyring' => ['sessions' => ['absolute' => '7d', 'levels' => ['aal2' => ['idle' => '30m']]], 'features' => [Features::devices()]]]);

    new KeyringServiceProvider($this->app)->register();

    expect(config('keyring.sessions.absolute'))->toBe('7d')
        ->and(config('keyring.sessions.middleware'))->toBeTrue()
        ->and(config('keyring.sessions.levels.aal2'))->toBe(['idle' => '30m', 'absolute' => '24h'])
        ->and(config('keyring.sessions.levels.aal3'))->toBe(['idle' => '15m', 'absolute' => '12h'])
        ->and(config('keyring.features'))->toBe([Features::devices()])
        ->and(config('keyring.limits.per_ip'))->toBe(20);
});

it('refuses a feature it doesn\'t know, rather than leaving it off', function () {
    config(['keyring.features' => [Features::registration(), 'device']]);

    new KeyringServiceProvider($this->app)->boot();
})->throws(UnknownFeature::class, 'Unknown Keyring features in config/keyring.php: [device]');
