<?php

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Keyring\Facades\Keyring;
use Keyring\Features;
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

it('renders the reset page whatever the query string holds', function () {
    $this->inertia()->get('/reset-password/a-token?email[]=x')
        ->assertOk()
        ->assertJsonPath('props.email', '');
});

it('ends outstanding reset links when the password is changed', function (bool $signOutOthers) {
    $token = Password::broker()->createToken($this->plain);

    $this->actingAs($this->plain)->freshAt(now())->putJson(route('user-password.update'), [
        'current_password' => 'password',
        'password' => 'a brand new passphrase',
        'password_confirmation' => 'a brand new passphrase',
        'sign_out_others' => $signOutOthers,
    ])->assertOk();
    auth()->logout();

    $this->post(route('password.update'), ['token' => $token, 'email' => 'plain@example.com', 'password' => 'attacker set passphrase', 'password_confirmation' => 'attacker set passphrase'])
        ->assertSessionHasErrors('email');
    expect(Hash::check('a brand new passphrase', $this->plain->fresh()->password))->toBeTrue();

    // A link asked for afterwards still works.
    $token = Password::broker()->createToken($this->plain->fresh());
    $this->post(route('password.update'), ['token' => $token, 'email' => 'plain@example.com', 'password' => 'another brand new passphrase', 'password_confirmation' => 'another brand new passphrase'])
        ->assertRedirect(route('login'));
    expect(Hash::check('another brand new passphrase', $this->plain->fresh()->password))->toBeTrue();
})->with(['signing others out' => true, 'staying signed in elsewhere' => false]);

it('keeps a reset link working after a refused new password', function () {
    $token = Password::broker()->createToken($this->plain);

    $this->post(route('password.update'), ['token' => $token, 'email' => 'plain@example.com', 'password' => 'tenchars12', 'password_confirmation' => 'tenchars12'])
        ->assertSessionHasErrors('password');
    $this->post(route('password.update'), ['token' => $token, 'email' => 'plain@example.com', 'password' => 'a brand new passphrase', 'password_confirmation' => 'a brand new passphrase'])
        ->assertRedirect(route('login'));

    expect(Hash::check('a brand new passphrase', $this->plain->fresh()->password))->toBeTrue();
});

it('changes the password and deletes the user when resets are off and the token table was never migrated', function () {
    withFeatures([Features::updatePasswords()]);
    config(['auth.passwords.users.table' => 'never_migrated']);

    $this->actingAs($this->plain)->freshAt(now())->putJson(route('user-password.update'), [
        'current_password' => 'password',
        'password' => 'a brand new passphrase',
        'password_confirmation' => 'a brand new passphrase',
    ])->assertOk();
    $this->plain->fresh()->delete();

    expect(User::find($this->plain->id))->toBeNull();
});
