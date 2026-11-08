<?php

use Illuminate\Support\Facades\Route;
use Keyring\Facades\Keyring;
use Keyring\KeyringManager;

it('registers the manager and merges config', function () {
    expect(Keyring::getFacadeRoot())->toBeInstanceOf(KeyringManager::class)
        ->and(config('keyring.username'))->toBe('email');
});

it('lets apps register the routes themselves, e.g. under a prefix', function () {
    Route::prefix('account')->group(fn () => Keyring::routes());

    $this->inertia()->get('/account/login')->assertOk()->assertJsonPath('component', 'auth/login');
});

it('takes the session lock on routes that spend session state', function (string $name) {
    expect(Route::getRoutes()->getByName($name)->locksFor())->toBeGreaterThan(0);
})->with([
    'login.store', 'keyring.login.factor', 'keyring.login.verify', 'keyring.login.send',
    'keyring.confirm.verify', 'keyring.confirm.send', 'keyring.authenticators.confirm',
]);
