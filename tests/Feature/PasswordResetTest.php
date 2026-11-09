<?php

use Illuminate\Support\Facades\Password;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    $this->plain = User::create(['name' => 'Plain', 'email' => 'plain@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    $this->mfa = User::create(['name' => 'Mfa', 'email' => 'mfa@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    Authenticator::factory()->totp()->for($this->mfa, 'authenticatable')->create();
});

it('answers a bad token the same way whether or not the account exists or has mfa', function () {
    $errors = collect(['plain@example.com', 'mfa@example.com', 'nobody@example.com'])->map(function (string $email) {
        $this->post(route('password.update'), ['token' => 'bogus', 'email' => $email, 'password' => 'tenchars12', 'password_confirmation' => 'tenchars12']);

        return $this->sessionErrors()->toArray();
    });

    expect($errors->unique()->count())->toBe(1)
        ->and($errors->first())->toHaveKey('email')->not->toHaveKey('password');
});

it('still applies the password rules once the token checks out', function () {
    $token = Password::broker()->createToken($this->plain);

    $this->post(route('password.update'), ['token' => $token, 'email' => 'plain@example.com', 'password' => 'tenchars12', 'password_confirmation' => 'tenchars12'])
        ->assertSessionHasErrors('password');

    $token = Password::broker()->createToken($this->mfa);

    $this->post(route('password.update'), ['token' => $token, 'email' => 'mfa@example.com', 'password' => 'tenchars12', 'password_confirmation' => 'tenchars12'])
        ->assertSessionHasNoErrors()
        ->assertRedirect(route('login'));
});

it('renders the reset page with a custom non-inertia page', function () {
    Keyring::page('reset-password', fn (array $props) => 'reset page for '.$props['email']);

    $this->get(route('password.reset', ['token' => 'abc', 'email' => 'plain@example.com']))
        ->assertOk()
        ->assertSee('reset page for plain@example.com')
        ->assertHeader('Referrer-Policy', 'no-referrer');
});
