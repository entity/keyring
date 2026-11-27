<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Enums\Assurance;
use Keyring\Events\EnrollmentRefused;
use Keyring\Events\FactorFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Testing\VirtualAuthenticator;

// Whoever copied the cookie of a session that just signed in has its fresh
// verification, but not the password. Without one, giving a password-only
// account a second factor would leave the owner asked for one they don't
// have, or someone else holding a passkey.
beforeEach(function () {
    Keyring::require(Requirement::aal2()->ifEnrolled());

    $this->user = taylor();
});

function signInOnlyWithPassword(): void
{
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
}

/**
 * @param  array<string, mixed>  $data
 */
function addAppFromSession(array $data = []): ?string
{
    $started = test()->postJson(route('keyring.authenticators.store', 'totp'), $data);

    if (! $started->isOk()) {
        return null;
    }

    test()->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($started->json('enrollment.secret'))])->assertOk();

    return $started->json('enrollment.secret');
}

describe('a password-only account', function () {
    beforeEach(function () {
        signInOnlyWithPassword();
    });

    it('refuses an authenticator app the session adds without the password', function () {
        Event::fake([EnrollmentRefused::class]);

        $this->postJson(route('keyring.authenticators.store', 'totp'))
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['password' => __('keyring::keyring.password_to_add_factor')]);

        Event::assertDispatched(EnrollmentRefused::class, fn (EnrollmentRefused $event) => $event->reason === 'password' && $event->factor === 'totp');
        expect($this->user->keyring->refresh()->all()->pluck('factor')->all())->toBe(['password']);

        // The owner still signs in with the password alone.
        $this->post('/logout');
        $this->flushSession();
        signInOnlyWithPassword();
        $this->assertAuthenticatedAs($this->user);
    });

    it('refuses a passkey the session adds without the password', function () {
        $this->postJson(route('keyring.authenticators.store', 'passkey'))
            ->assertJsonValidationErrors(['password' => __('keyring::keyring.password_to_add_factor')]);

        expect($this->user->keyring->refresh()->of('passkey'))->toBeEmpty();
    });

    it('adds one with the password, typed when it begins', function () {
        $secret = addAppFromSession(['password' => 'password']);

        expect($this->user->keyring->refresh()->of('totp')->sole()->secret)->toBe($secret)
            ->and($this->user->keyring->of('recovery'))->toHaveCount(1);
    });

    it('adds a passkey with the password', function () {
        $key = new VirtualAuthenticator;
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->assertOk()->json('enrollment.options');
        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();

        expect($this->user->keyring->refresh()->of('passkey'))->toHaveCount(1);
    });

    it('refuses a wrong password, which counts as a failed one', function () {
        Event::fake([EnrollmentRefused::class, FactorFailed::class]);

        $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'wrong'])
            ->assertJsonValidationErrors(['password' => __('validation.current_password')]);

        Event::assertDispatched(FactorFailed::class, fn (FactorFailed $event) => $event->factor === 'password');
        Event::assertDispatched(EnrollmentRefused::class, fn (EnrollmentRefused $event) => $event->reason === 'password');
        expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();
    });

    it('holds wrong passwords to the password\'s rate limits', function () {
        config(['keyring.limits.per_account' => 2]);

        $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'wrong'])->assertUnprocessable();
        $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'wrong'])->assertUnprocessable();
        $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])
            ->assertStatus(429)
            ->assertJsonValidationErrors('password');
    });

    it('takes the password once, for the enrollment it began', function () {
        $started = $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->assertOk();
        $code = totpCode($started->json('enrollment.secret'));
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => $code])->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => $code])->assertJsonValidationErrors('code');

        // The app it just added is no older than one the session could add.
        $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertJsonValidationErrors('password');
    });

    it('doesn\'t ask for an emailed code, which isn\'t a second factor', function () {
        Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, EmailCode::asExtraStep()]);

        $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
    });
});

it('asks again at the confirm when the account lost its established factor since', function () {
    $totp = Authenticator::factory()->totp()->established()->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user)->verifiedWith($totp);
    $key = new VirtualAuthenticator;
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');

    $totp->forceFill(['created_at' => now()])->save();

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])
        ->assertJsonValidationErrors(['password' => __('keyring::keyring.password_to_add_factor')]);
    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])
        ->assertJsonValidationErrors(['credential' => __('keyring::keyring.enrollment_expired')]);

    expect($this->user->keyring->refresh()->of('passkey'))->toBeEmpty();
});

it('asks for the password when the only second factor is as new as one a session could add', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['created_at' => now()->subHours(2)]);
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

    $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertJsonValidationErrors('password');
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertJsonValidationErrors('password');
    $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->assertOk();

    // Recovery codes aren't a second factor of their own.
    $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();
});

it('doesn\'t ask once the account has an established second factor', function () {
    Authenticator::factory()->totp()->established()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->established()->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

    $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk();
});

it('adds the first factor of an account without a password with no password to type', function () {
    $this->user->forceFill(['password' => null])->saveQuietly();
    Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

    expect(app(AuthenticatorChanges::class)->needsPassword($this->user, Keyring::factor('totp')))->toBeFalse();

    addAppFromSession();

    expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
});

it('takes the password from a user keyring.enrolled sends to add their first factor', function () {
    Route::middleware(['web', 'keyring.enrolled'])->get('/home', fn () => 'home');
    config(['keyring.enrollment_url' => '/settings/security']);
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->get('/home')->assertRedirect('/settings/security');
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertJsonValidationErrors('password');
    addAppFromSession(['password' => 'password']);

    $this->get('/home')->assertOk();
});

it('has no password to ask for where the app doesn\'t sign in with one', function () {
    Keyring::factors([WebAuthn::passkeys(), Totp::class, RecoveryCodes::class]);
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});

describe('your own code', function () {
    it('needs to say it made sure who it\'s adding for', function () {
        $factor = Keyring::factor('totp');

        expect(fn () => app(AuthenticatorChanges::class)->add($this->user, $factor, Authenticator::factory()->totp()->make()))
            ->toThrow(ValidationException::class, __('keyring::keyring.password_to_add_factor'));

        app(AuthenticatorChanges::class)->add($this->user, $factor, Authenticator::factory()->totp()->make(), passwordConfirmed: true);

        expect($this->user->keyring->refresh()->of('totp'))->toHaveCount(1);
    });
});
