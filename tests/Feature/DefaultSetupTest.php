<?php

declare(strict_types=1);

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Tests\Fixtures\PlainUser;

/**
 * Keyring as it ships: the package's default config, the password alone, and
 * a user model without MustVerifyEmail, as in the Quick Start.
 */
beforeEach(function () {
    $defaults = require __DIR__.'/../../config/keyring.php';
    config(['keyring' => $defaults, 'auth.providers.users.model' => PlainUser::class]);
    Keyring::factors([Password::class]);
    withFeatures($defaults['features']);
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->delete('/account', fn () => 'deleted');
});

it('registers, signs out and signs back in', function () {
    $this->post('/register', [
        'name' => 'Taylor',
        'email' => 'taylor@example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
    ])->assertRedirect('/dashboard');

    $this->assertAuthenticated();
    $this->post('/logout');
    $this->assertGuest();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])->assertRedirect('/dashboard');
    $this->assertAuthenticated();
});

it('resets a forgotten password', function () {
    Notification::fake();
    $user = PlainUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'an old long passphrase']);

    $this->post('/forgot-password', ['email' => 'taylor@example.com'])->assertSessionHas('status');

    $token = null;
    Notification::assertSentTo($user, ResetPassword::class, function (ResetPassword $notice) use (&$token) {
        $token = $notice->token;

        return true;
    });

    $this->post('/reset-password', [
        'token' => $token,
        'email' => 'taylor@example.com',
        'password' => 'a brand new long passphrase',
        'password_confirmation' => 'a brand new long passphrase',
    ])->assertRedirect();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new long passphrase'])->assertRedirect('/dashboard');
});

it('asks for the password again before a sensitive route', function () {
    $user = PlainUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'a long passphrase here']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a long passphrase here']);
    $this->travel(16)->minutes();

    $this->delete('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->get(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'a long passphrase here']);

    $this->delete('/account')->assertOk()->assertSee('deleted');
});
