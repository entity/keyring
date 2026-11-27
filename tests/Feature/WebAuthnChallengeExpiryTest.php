<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Models\Authenticator;
use Keyring\Testing\VirtualAuthenticator;

// A challenge is for the prompt it was issued to. The browser gives up on
// that after "webauthn.timeout", but the server has to stop taking the
// answer too, or a challenge is good for as long as whatever holds it.
beforeEach(function () {
    Keyring::factors([Password::class, Totp::class, WebAuthn::passkeys(), WebAuthn::securityKeys(), RecoveryCodes::class]);

    $this->user = taylor();
    $this->key = new VirtualAuthenticator;
});

function enrollKey(string $factor, VirtualAuthenticator $key): void
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL2);

    $options = test()->postJson(route('keyring.authenticators.store', $factor), ['password' => 'password'])->assertOk()->json('enrollment.options');
    test()->postJson(route('keyring.authenticators.confirm', $factor), ['credential' => $key->register($options)])->assertOk();

    test()->post('/logout');
}

describe('the challenge of a usernameless sign in', function () {
    beforeEach(function () {
        enrollKey('passkey', $this->key);

        $this->issued = $this->getJson(route('keyring.login.options', 'passkey'))->assertOk()->json('options');
    });

    it('is refused once it is older than the setting allows, though the session still holds it', function (int $minutes) {
        $this->travel($minutes)->minutes();

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($this->issued)])
            ->assertSessionHasErrors('credential');
        $this->assertGuest();

        // The page asks for another and carries on.
        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($options)])->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
    })->with([
        'just past five minutes' => 6,
        'most of a session later' => 100,
    ]);

    it('is good until then', function () {
        $this->travel(299)->seconds();

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($this->issued)])->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
    });

    it('is spent by an answer that came too late', function () {
        $this->travel(6)->minutes();
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($this->issued)])->assertSessionHasErrors('credential');

        $this->travelBack();
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($this->issued)])->assertSessionHasErrors('credential');
        $this->assertGuest();
    });

    it('lasts as long as the app sets', function () {
        config(['keyring.webauthn.login_options_for' => '90s']);
        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');

        $this->travel(91)->seconds();

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($options)])->assertSessionHasErrors('credential');
        $this->assertGuest();
    });

    it('never runs out before the browser has stopped waiting', function () {
        config(['keyring.webauthn.timeout' => '10m']);
        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');

        expect($options['timeout'])->toBe(600_000);

        $this->travel(9)->minutes();
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($options)])->assertRedirect('/dashboard');
    });

    it('is refused when what the session holds says nothing of when it was issued', function () {
        session(['keyring.webauthn.login.passkey' => session('keyring.webauthn.login.passkey')['options']]);

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($this->issued)])->assertSessionHasErrors('credential');
        $this->assertGuest();
    });
});

// These two are kept in what they belong to, and run out when it does.
it('refuses the challenge of a second factor once the sign in it belongs to has run out', function () {
    $key = new VirtualAuthenticator(userVerification: false);
    enrollKey('security-key', $key);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
    $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
    $this->flushHeaders();

    $this->travel(11)->minutes();

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])->assertRedirect(route('login'));
    $this->assertGuest();
});

it('refuses the challenge of a step-up once the confirmation it belongs to has run out', function () {
    Route::middleware(['web', 'auth', 'keyring.fresh:5m'])->get('/billing', fn () => 'billing');
    enrollKey('passkey', $this->key);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());
    $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    $options = $this->inertia()->get(route('keyring.confirm.challenge', 'passkey'))->assertOk()->json('props.challenge.options');
    $this->flushHeaders();

    $this->travel(11)->minutes();

    $this->post(route('keyring.confirm.verify', 'passkey'), ['credential' => $this->key->assert($options)]);
    $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
});

it('refuses the challenge of a new key once the enrollment it belongs to has run out', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->assertOk()->json('enrollment.options');

    $this->travel(16)->minutes();
    // Still signed in and freshly verified, so only the enrollment has aged.
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $this->key->register($options)])
        ->assertJsonValidationErrors(['credential' => __('keyring::keyring.enrollment_expired')]);

    expect(Authenticator::query()->where('factor', 'passkey')->exists())->toBeFalse();
});
