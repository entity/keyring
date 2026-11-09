<?php

use Illuminate\Support\Facades\Route;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Factors\FactorRegistry;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Features;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\SecurityEvent;

beforeEach(function () {
    $this->user = taylor();
});

it('only has signing in, challenges, step-up and signing out without features', function () {
    withFeatures([]);

    expect(collect(['login', 'login.store', 'keyring.login.challenge', 'keyring.confirm.challenge', 'logout'])->every(fn (string $name) => Route::has($name)))->toBeTrue()
        ->and(collect(['register', 'password.request', 'verification.notice', 'user-password.update', 'keyring.authenticators.store', 'keyring.devices.index', 'keyring.devices.report', 'keyring.email.store', 'keyring.email.confirm'])->filter(fn (string $name) => Route::has($name))->all())->toBe([]);
});

it('adds each feature\'s routes once it\'s on', function (string $feature, array $routes) {
    withFeatures([$feature]);

    expect(collect($routes)->every(fn (string $name) => Route::has($name)))->toBeTrue();
})->with([
    'registration' => [Features::registration(), ['register', 'register.store']],
    'reset passwords' => [Features::resetPasswords(), ['password.request', 'password.email', 'password.reset', 'password.update']],
    'email verification' => [Features::emailVerification(), ['verification.notice', 'verification.verify', 'verification.send']],
    'update passwords' => [Features::updatePasswords(), ['user-password.update']],
    'manage authenticators' => [Features::manageAuthenticators(), ['keyring.authenticators.store', 'keyring.authenticators.confirm', 'keyring.authenticators.update', 'keyring.authenticators.destroy']],
    'devices' => [Features::devices(), ['keyring.devices.index', 'keyring.devices.destroy', 'keyring.devices.destroy-others', 'keyring.devices.report']],
    'email changes' => [Features::emailChanges(), ['keyring.email.show', 'keyring.email.store', 'keyring.email.destroy', 'keyring.email.confirm', 'keyring.email.revert']],
]);

it('signs in without a device cookie or security log rows when those are off', function () {
    withFeatures([]);

    $this->post(route('login.store'), ['email' => $this->user->email, 'password' => 'password'])
        ->assertRedirect('/dashboard')
        ->assertCookieMissing('keyring_device');

    $this->assertAuthenticatedAs($this->user);
    expect(Device::count())->toBe(0)
        ->and(SecurityEvent::count())->toBe(0);
});

it('records the device and the sign in once those are on', function () {
    withFeatures([Features::devices(), Features::securityLog()]);

    $this->post(route('login.store'), ['email' => $this->user->email, 'password' => 'password'])
        ->assertCookie('keyring_device');

    expect(Device::count())->toBe(1)
        ->and(SecurityEvent::where('type', 'signed_in')->count())->toBe(1);
});

it('lets the app change the email and password itself until keyring handles them', function () {
    withFeatures([]);
    $this->user->update(['email' => 'new@example.com', 'password' => 'a new password here']);

    withFeatures([Features::updatePasswords()]);
    $this->user->update(['email' => 'newer@example.com']);
    expect(fn () => $this->user->update(['password' => 'another new password']))->toThrow(ProtectedAttributeException::class);

    withFeatures([Features::emailChanges()]);
    expect(fn () => $this->user->fresh()->update(['email' => 'newest@example.com']))->toThrow(ProtectedAttributeException::class);
});

it('only offers to trust the device when devices are on', function () {
    Keyring\Facades\Keyring::factors([Password::class, Totp::class]);
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    withFeatures([]);

    $this->post(route('login.store'), ['email' => $this->user->email, 'password' => 'password']);

    $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.canTrustDevice', false);
});

it('starts with the password, registration, password resets and no emails', function () {
    $config = require __DIR__.'/../../config/keyring.php';

    expect(new FactorRegistry(app())->all()->keys()->all())->toBe(['password'])
        ->and($config['features'])->toBe([Features::registration(), Features::resetPasswords()])
        ->and($config['notifications'])->toBe([])
        ->and($config['protected'])->toBe([]);
});
