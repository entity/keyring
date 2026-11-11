<?php

declare(strict_types=1);

use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;

beforeEach(function () {
    $this->user = taylor();
});

it('refuses removals that would leave the account below its policy once recovery codes go too', function () {
    Keyring::require(Requirement::aal2());
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)
        ->deleteJson(route('keyring.authenticators.destroy', $totp->id))
        ->assertUnprocessable()
        ->assertJsonValidationErrors('authenticator');

    expect($this->user->keyring->refresh()->all()->pluck('factor')->sort()->values()->all())->toBe(['password', 'recovery', 'totp']);
});

it('needs every factor signing in would, not just one, to manage authenticators', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->default()->create();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->freshAt(now()->subHour());

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);
    $this->inertia()->get(route('keyring.confirm.challenge'))->assertJsonPath('props.factor', 'totp');
    $this->flushHeaders();

    // One factor isn't enough for a user with two.
    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)]);
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});

it('still lets password-only users confirm with their password', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});

it('refuses to enroll authenticators until the email address is verified', function () {
    // Only signed in at all where registration signs new users in.
    revealTakenAddresses();
    $this->user->forceFill(['email_verified_at' => null])->save();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'totp'))
        ->assertForbidden();
});

it('does not count a security key as a way to sign in on its own', function () {
    $this->user->forceFill(['password' => null])->saveQuietly();
    $passkey = Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'passkey', 'name' => 'Passkey', 'credential_id' => 'a']);
    Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'security-key', 'name' => 'Key', 'credential_id' => 'b']);

    Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()]);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL3)
        ->deleteJson(route('keyring.authenticators.destroy', $passkey->id))
        ->assertUnprocessable();
});

it('never makes recovery codes the default', function () {
    $codes = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)
        ->patchJson(route('keyring.authenticators.update', $codes->id), ['default' => true])
        ->assertJsonValidationErrors('default');
});
