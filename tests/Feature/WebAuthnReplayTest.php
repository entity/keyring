<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Models\Authenticator;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\WebAuthn\SpentChallenges;

// Laravel's "cookie" session driver keeps the session in the browser, which
// can send back an earlier copy of it: one that still holds a challenge that
// has since been answered. A key that counts its signatures gives a second
// use of its answer away. A synced passkey's count stays at zero, so these
// keys don't count, and only the server remembering the challenge refuses
// the answer the second time.
beforeEach(function () {
    Keyring::factors([Password::class, Totp::class, WebAuthn::passkeys(), WebAuthn::securityKeys(), RecoveryCodes::class]);
    config(['keyring.limits.per_account' => 100]);

    $this->user = taylor();
    $this->key = new VirtualAuthenticator(synced: true, counts: false);
});

function addKey(string $factor, VirtualAuthenticator $key): void
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL2);

    $options = test()->postJson(route('keyring.authenticators.store', $factor), ['password' => 'password'])->assertOk()->json('enrollment.options');
    test()->postJson(route('keyring.authenticators.confirm', $factor), ['credential' => $key->register($options)])->assertOk();

    test()->post('/logout');
}

describe('a browser that sends back an earlier copy of its session', function () {
    it('cannot sign in without a username with an answer a second time', function () {
        addKey('passkey', $this->key);

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $unanswered = session()->all();
        $answer = $this->key->assert($options);

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $answer])->assertRedirect('/dashboard');
        $this->post('/logout');

        sendBackSession($unanswered);

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $answer])
            ->assertSessionHasErrors(['credential' => __('auth.failed')]);
        $this->assertGuest();
    });

    it('cannot answer a usernameless challenge again once an answer to it has failed', function (string $wrong) {
        addKey('passkey', $this->key);

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $unanswered = session()->all();

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => match ($wrong) {
            'origin' => $this->key->assert($options, 'https://evil.example'),
            'key' => new VirtualAuthenticator()->assert($options),
            'nonsense' => 'nonsense',
        }])->assertSessionHasErrors(['credential' => __('auth.failed')]);

        sendBackSession($unanswered);

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($options)])
            ->assertSessionHasErrors(['credential' => __('auth.failed')]);
        $this->assertGuest();
    })->with([
        'from another origin' => 'origin',
        'from a key nobody has' => 'key',
        'that was no credential at all' => 'nonsense',
    ]);

    it('uses a usernameless challenge up before it looks for whose key answered', function () {
        addKey('passkey', $this->key);

        $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $issued = session('keyring.webauthn.login.passkey.options');
        $marks = fn () => Cache::store(config('cache.limiter'))->has('keyring:challenge:'.sha1($issued));

        expect($marks())->toBeFalse();

        // A key nobody has costs the server what a real one does.
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => new VirtualAuthenticator()->assert(json_decode($issued, true))]);

        expect($marks())->toBeTrue();
    });

    it('cannot pass a second factor challenge with an answer a second time', function () {
        $key = new VirtualAuthenticator(userVerification: false, counts: false);
        addKey('security-key', $key);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
        $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
        $this->flushHeaders();
        $unanswered = session()->all();
        $answer = $key->assert($options);

        $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $answer])->assertRedirect('/dashboard');
        $this->post('/logout');

        // The copy still has the password proved, so the answer alone
        // would finish the sign in.
        sendBackSession($unanswered);

        $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $answer])
            ->assertSessionHasErrors(['credential' => __('keyring::keyring.invalid')]);
        $this->assertGuest();
    });

    it('cannot answer a second factor challenge again once an answer to it has failed', function () {
        $key = new VirtualAuthenticator(userVerification: false, counts: false);
        addKey('security-key', $key);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
        $this->flushHeaders();
        $unanswered = session()->all();

        $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options, 'https://evil.example')])
            ->assertSessionHasErrors('credential');

        sendBackSession($unanswered);

        $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])
            ->assertSessionHasErrors(['credential' => __('keyring::keyring.invalid')]);
        $this->assertGuest();
    });

    it('cannot step up with an answer a second time', function () {
        Route::middleware(['web', 'auth', 'keyring.fresh:5m'])->get('/billing', fn () => 'billing');
        addKey('passkey', $this->key);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        $options = $this->inertia()->get(route('keyring.confirm.challenge', 'passkey'))->assertOk()->json('props.challenge.options');
        $this->flushHeaders();
        $unanswered = session()->all();
        $answer = $this->key->assert($options);

        $this->post(route('keyring.confirm.verify', 'passkey'), ['credential' => $answer])->assertSessionHasNoErrors();
        $this->get('/billing')->assertOk();

        sendBackSession($unanswered);

        $this->actingAs($this->user)->post(route('keyring.confirm.verify', 'passkey'), ['credential' => $answer])
            ->assertSessionHasErrors(['credential' => __('keyring::keyring.invalid')]);
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('cannot add a key with a challenge that an answer has already failed', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->assertOk()->json('enrollment.options');
        $unconfirmed = session()->all();

        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => new VirtualAuthenticator(origin: 'https://evil.example')->register($options)])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['credential' => __('keyring::keyring.invalid')]);

        sendBackSession($unconfirmed);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL2)
            ->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $this->key->register($options)])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['credential' => __('keyring::keyring.enrollment_expired')]);

        expect(Authenticator::query()->where('factor', 'passkey')->exists())->toBeFalse();
    });

    it('cannot add a key again with the answer that added it', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->assertOk()->json('enrollment.options');
        $unconfirmed = session()->all();
        $answer = $this->key->register($options);

        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $answer])->assertOk();
        // Removed again, with the recovery codes that came with it.
        Authenticator::query()->delete();
        $this->user->keyring->refresh();

        sendBackSession($unconfirmed);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL2)
            ->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $answer])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['credential' => __('keyring::keyring.enrollment_expired')]);

        expect(Authenticator::query()->where('factor', 'passkey')->exists())->toBeFalse();
    });
});

it('still takes each new challenge from a key that never counts', function () {
    addKey('passkey', $this->key);

    foreach (range(1, 3) as $signIn) {
        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $this->key->assert($options)])->assertRedirect('/dashboard');
        $this->post('/logout');
    }
});

it('remembers an answered challenge until it would have expired, and no longer', function () {
    $challenges = app(SpentChallenges::class);
    $expiresAt = now()->addMinutes(5)->getTimestamp();

    expect($challenges->spend('{"challenge":"first"}', $expiresAt))->toBeTrue()
        ->and($challenges->spend('{"challenge":"first"}', $expiresAt))->toBeFalse()
        ->and($challenges->spend('{"challenge":"second"}', $expiresAt))->toBeTrue();

    $this->travel(299)->seconds();

    expect($challenges->spend('{"challenge":"first"}', $expiresAt))->toBeFalse();

    // Past that the challenge itself is refused wherever it's kept, and
    // nothing is left behind for it.
    $this->travel(3)->seconds();

    expect(Cache::store(config('cache.limiter'))->has('keyring:challenge:'.sha1('{"challenge":"first"}')))->toBeFalse();
});
