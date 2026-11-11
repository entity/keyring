<?php

use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\KeyringServiceProvider;
use Keyring\Tests\Fixtures\User;

/**
 * Keyring as it ships: the package's default config, the password alone, and
 * a user model that verifies its email, as in the Quick Start.
 */
beforeEach(function () {
    Notification::fake();

    $defaults = require __DIR__.'/../../config/keyring.php';
    config(['keyring' => $defaults, 'auth.providers.users.model' => User::class]);
    Keyring::factors([Password::class]);
    withFeatures($defaults['features']);
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->delete('/account', fn () => 'deleted');
});

it('boots with the features it ships with', function () {
    new KeyringServiceProvider($this->app)->boot();
})->throwsNoExceptions();

it('registers, verifies the address, signs out and signs back in', function () {
    $this->post('/register', [
        'name' => 'Taylor',
        'email' => 'taylor@example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
    ])->assertRedirect(route('login'));

    $this->assertGuest();
    $user = User::sole();

    $link = null;
    Notification::assertSentTo($user, VerifyEmail::class, function (VerifyEmail $notification) use ($user, &$link) {
        $link = $notification->toMail($user)->actionUrl;

        return true;
    });

    $this->get($link)->assertRedirect(route('login'));
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])->assertRedirect($link);

    $this->assertAuthenticated();
    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();

    $this->post('/logout');
    $this->assertGuest();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])->assertRedirect('/dashboard');
    $this->assertAuthenticated();
});

it('does not say whether an address already has an account when someone registers with it', function () {
    User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'an old long passphrase', 'email_verified_at' => now()]);

    $this->post('/register', [
        'name' => 'Someone Else',
        'email' => 'taylor@example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
    ])->assertRedirect(route('login'))->assertSessionHasNoErrors();

    expect(User::count())->toBe(1);
});

it('lets a user change their password', function () {
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'an old long passphrase', 'email_verified_at' => now()]);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'an old long passphrase']);

    $this->put('/user/password', [
        'current_password' => 'an old long passphrase',
        'password' => 'a brand new long passphrase',
        'password_confirmation' => 'a brand new long passphrase',
    ])->assertSessionHasNoErrors()->assertSessionHas('status', 'password-updated');

    expect(Hash::check('a brand new long passphrase', $user->fresh()->password))->toBeTrue()
        ->and(fn () => $user->fresh()->forceFill(['password' => 'changed some other way'])->save())->toThrow(ProtectedAttributeException::class);
});

it('resets a forgotten password', function () {
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'an old long passphrase', 'email_verified_at' => now()]);

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
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'a long passphrase here', 'email_verified_at' => now()]);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a long passphrase here']);
    $this->travel(16)->minutes();

    $this->delete('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->get(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'a long passphrase here']);

    $this->delete('/account')->assertOk()->assertSee('deleted');
});
