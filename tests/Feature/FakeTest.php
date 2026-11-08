<?php

use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;

beforeEach(function () {
    Keyring::factors([Password::class, Totp::class, WebAuthn::securityKeys(), RecoveryCodes::class]);
    $this->user = taylor();
});

it('passes factors without real proofs', function () {
    Keyring::require(Requirement::aal2()->phishingResistant());
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    Keyring::fake()->pass('security-key');

    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.verify', 'security-key'))->assertRedirect('/dashboard');

    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
});

it('fails factors on demand', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Keyring::fake()->fail('totp');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '123456'])->assertSessionHasErrors('code');

    $this->assertGuest();
});

it('still identifies users for real', function () {
    Keyring::fake()->pass('password');

    $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'anything'])->assertSessionHasErrors('email');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'anything'])->assertRedirect('/dashboard');
});

it('enforces no downgrade for users with phishing resistant factors', function () {
    Keyring::require(Requirement::aal2()->noDowngrade());
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->default()->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $response = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'security-key');
    expect($response->json('props.alternatives'))->toBe([]);

    Keyring::fake()->pass('totp');
    $this->post(route('keyring.login.verify', 'totp'))->assertSessionHasErrors();
    $this->assertGuest();
});

it('still offers recovery codes under no downgrade, so a lost key is not a lockout', function () {
    Keyring::require(Requirement::aal2()->noDowngrade());
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $response = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'security-key');
    expect(collect($response->json('props.alternatives'))->pluck('factor')->all())->toBe(['recovery']);
    $this->flushHeaders();

    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaaa-11111'])->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('can refuse recovery codes under no downgrade as well', function () {
    Keyring::require(Requirement::aal2()->noDowngrade(except: []));
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    expect($this->inertia()->get(route('keyring.login.challenge'))->json('props.alternatives'))->toBe([]);
});
