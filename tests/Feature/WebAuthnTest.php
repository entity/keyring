<?php

use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Sessions\SessionAssurance;
use Keyring\Testing\VirtualAuthenticator;

beforeEach(function () {
    Keyring::factors([
        Password::class,
        Totp::class,
        WebAuthn::passkeys(),
        WebAuthn::securityKeys(),
        RecoveryCodes::class,
    ]);

    $this->user = taylor();
});

function enroll(string $factor, VirtualAuthenticator $key, string $name = 'My key'): void
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL2);

    $options = test()->postJson(route('keyring.authenticators.store', $factor))->assertOk()->json('enrollment.options');

    test()->postJson(route('keyring.authenticators.confirm', $factor), [
        'credential' => $key->register($options),
        'name' => $name,
    ])->assertOk();

    test()->post('/logout');
}

it('registers a passkey', function () {
    $key = new VirtualAuthenticator;

    enroll('passkey', $key, 'MacBook');

    $passkey = $this->user->keyring->of('passkey')->first();

    expect($passkey->name)->toBe('MacBook')
        ->and($passkey->meta('user_verified'))->toBeTrue()
        ->and($passkey->factor()->categories($passkey))->toBe([Category::Possession, Category::Inherence]);
});

it('signs in with a passkey alone, without a username', function (VirtualAuthenticator $key) {
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))
        ->assertOk()
        ->assertJsonPath('allowCredentials', [])
        ->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
})->with([
    'P-256' => fn () => new VirtualAuthenticator,
    'Ed25519' => fn () => VirtualAuthenticator::eddsa(),
]);

it('uses a security key as a second factor', function () {
    $key = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $key);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $options = $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.factor', 'security-key')
        ->json('props.challenge.options');

    expect($options['allowCredentials'])->toHaveCount(1);

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
});

it('does not let a security key sign in without a password', function () {
    $key = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $key);

    $this->getJson(route('keyring.login.options', 'security-key'))->assertNotFound();

    $this->post(route('keyring.login.factor', 'security-key'), ['credential' => $key->assert(['challenge' => 'x', 'rpId' => 'localhost'])])
        ->assertNotFound();

    $this->assertGuest();
});

it('only counts inherence when the key verified the user', function () {
    Keyring::require(Requirement::factors(3));
    $key = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $key);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)]);

    $this->assertGuest();
});

it('accepts any of the user\'s keys, not just the one shown', function () {
    $first = new VirtualAuthenticator(userVerification: false);
    $second = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $first, 'First');
    enroll('security-key', $second, 'Second');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $options = $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.authenticator.name', 'First')
        ->json('props.challenge.options');

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $second->assert($options)])
        ->assertRedirect('/dashboard');

    expect($this->user->keyring->refresh()->of('security-key')->firstWhere('name', 'Second')->last_used_at)->not->toBeNull();
});

it('rejects responses from another origin', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options, origin: 'https://evil.example')])
        ->assertSessionHasErrors('credential');

    $this->assertGuest();
});

it('rejects a replayed challenge', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $credential = $key->assert($options);

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $credential])->assertRedirect('/dashboard');
    $this->post('/logout');

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $credential])->assertSessionHasErrors('credential');
    $this->assertGuest();
});

it('rejects a cloned key whose counter went backwards', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)]);
    $this->post('/logout');

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->rewindCounter()->assert($options)])
        ->assertSessionHasErrors('credential');
});

it('will not register the same key twice', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');

    expect($options['excludeCredentials'])->toHaveCount(1);

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])
        ->assertUnprocessable();
});

it('lets a passkey satisfy a phishing resistant policy', function () {
    Keyring::require(Requirement::aal2()->phishingResistant());
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);
    $this->travel(1)->minutes();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $response = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'passkey');

    expect(collect($response->json('props.alternatives'))->pluck('factor'))->not->toContain('totp', 'recovery');

    $this->post(route('keyring.login.verify', 'passkey'), ['credential' => $key->assert($response->json('props.challenge.options'))])
        ->assertRedirect('/dashboard');
});
