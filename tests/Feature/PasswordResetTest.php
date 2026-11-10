<?php

use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Events\FactorVerified;
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
        ->assertHeader('Referrer-Policy', 'same-origin');
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

// A reset signs out the sessions registered by then. A sign in that checked
// the old password just before is registered just after.
it('does not leave a sign in that was under way during a reset signed in', function () {
    $user = taylor();

    // The reset, start to finish, between the password check and the session.
    Event::listen(fn (FactorVerified $event) => app(PasswordChanges::class)->reset(
        $owner = $user->fresh(),
        fn () => $owner->forceFill(['password' => 'a-brand-new-long-password-1'])->save(),
    ));

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
    expect(app(SessionRegistry::class)->forUser($user))->toBeEmpty();
});

// Checking a password can rehash it, which writes the typed password back.
// A reset that finished in between has stored a new one.
it('does not let a rehash put back the password a reset replaced while it was being checked', function () {
    $user = taylor();

    // A hasher that wants a rehash, and plays the whole reset just before it
    // checks: after the sign in loaded the user, before it saves anything.
    Hash::extend('racing', fn () => new class(['rounds' => 5]) extends BcryptHasher
    {
        public static ?Closure $before = null;

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = [])
        {
            [$before, self::$before] = [self::$before, null];
            $before?->__invoke();

            return parent::check($value, $hashedValue, $options);
        }
    });
    config(['hashing.driver' => 'racing']);

    Hash::driver()::$before = fn () => app(PasswordChanges::class)->reset(
        $owner = $user->fresh(),
        fn () => $owner->forceFill(['password' => 'a-brand-new-long-password-1'])->save(),
    );

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
    expect(Hash::check('a-brand-new-long-password-1', $user->fresh()->password))->toBeTrue()
        ->and(app(SessionRegistry::class)->forUser($user))->toBeEmpty();
});

it('does not leave a browser trusted by a sign in that a reset ended', function () {
    withFeatures([Features::resetPasswords(), Features::devices()]);
    config(['keyring.devices.trust_for' => '30d']);
    $totp = $this->mfa->authenticators()->where('factor', 'totp')->sole();

    $this->post('/login', ['email' => 'mfa@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

    // The reset, start to finish, between the code check and the session.
    Event::listen(fn (FactorVerified $event) => $event->authenticator->factor === 'totp' && app(PasswordChanges::class)->reset(
        $owner = $this->mfa->fresh(),
        fn () => $owner->forceFill(['password' => 'a-brand-new-long-password-1'])->save(),
    ));

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret), 'trust' => true]);

    $this->assertGuest();
    expect(Keyring::deviceModel()::query()->whereNotNull('trusted_until')->count())->toBe(0);
});
