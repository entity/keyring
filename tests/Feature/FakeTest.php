<?php

use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Session\SessionAssurance;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Keyring::factors([Password::class, Totp::class, WebAuthn::securityKeys(), RecoveryCodes::class]);
    $this->user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);
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
