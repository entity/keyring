<?php

use Illuminate\Support\Facades\Event;
use Keyring\Events\AuthenticatorAdded;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\RecoveryCodesGenerated;
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function () {
    $this->user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
});

it('enrolls an authenticator app in two steps', function () {
    Event::fake([AuthenticatorAdded::class, RecoveryCodesGenerated::class]);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['name' => '1Password'])
        ->assertOk()
        ->assertJsonPath('factor', 'totp')
        ->assertJsonStructure(['enrollment' => ['secret', 'url', 'qr']])
        ->json('enrollment.secret');

    expect($this->user->keyring->refresh()->of('totp'))->toBeEmpty();

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000'])
        ->assertUnprocessable()
        ->assertJsonValidationErrors('code');

    $response = $this->postJson(route('keyring.authenticators.confirm', 'totp'), [
        'code' => app(Google2FA::class)->getCurrentOtp($secret),
    ])->assertOk()->assertJsonPath('authenticator.name', '1Password');

    expect($response->json('recoveryCodes'))->toHaveCount(8);

    $keyring = $this->user->keyring->refresh();
    expect($keyring->of('totp'))->toHaveCount(1)
        ->and($keyring->of('totp')->first()->is_default)->toBeTrue()
        ->and($keyring->of('recovery'))->toHaveCount(1);

    Event::assertDispatched(AuthenticatorAdded::class);
    Event::assertDispatched(RecoveryCodesGenerated::class);
});

it('only hands out recovery codes automatically the first time', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => app(Google2FA::class)->getCurrentOtp($secret)])
        ->assertOk()
        ->assertJsonMissingPath('recoveryCodes')
        ->assertJsonPath('authenticator.name', 'Authenticator app');
});

it('regenerates recovery codes, replacing the old ones', function () {
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $codes = $this->postJson(route('keyring.authenticators.store', 'recovery'))->json('enrollment.codes');
    $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

    $recovery = $this->user->keyring->refresh()->of('recovery');
    expect($recovery)->toHaveCount(1)
        ->and($codes)->toHaveCount(8)
        ->and($recovery->first()->factor()->present($recovery->first())['remaining'])->toBe(8);
});

it('renames and picks the default', function () {
    $first = Authenticator::factory()->totp()->default()->for($this->user, 'authenticatable')->create();
    $second = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->patchJson(route('keyring.authenticators.update', $second->id), ['name' => 'Work phone', 'default' => true])
        ->assertOk()
        ->assertJsonPath('authenticator.name', 'Work phone');

    expect($first->fresh()->is_default)->toBeFalse()
        ->and($second->fresh()->is_default)->toBeTrue();
});

it('cannot touch someone else\'s authenticators', function () {
    $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password']);
    $theirs = Authenticator::factory()->totp()->for($other, 'authenticatable')->create();

    $this->deleteJson(route('keyring.authenticators.destroy', $theirs->id))->assertNotFound();
});

it('removes an authenticator and drops recovery codes once nothing is left to recover', function () {
    Event::fake([AuthenticatorRemoved::class]);
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id))->assertOk();

    expect($this->user->keyring->refresh()->all()->pluck('factor')->all())->toBe(['password']);
    Event::assertDispatched(AuthenticatorRemoved::class);
});

it('refuses to remove the last factor the policy needs', function () {
    Keyring::require(Requirement::aal2());
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id))
        ->assertUnprocessable()
        ->assertJsonValidationErrors('authenticator');

    $second = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id))->assertOk();
    expect($second->fresh())->not->toBeNull();
});

it('needs a fresh verification to manage authenticators', function () {
    $this->travel(16)->minutes();

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);
});

it('404s for factors that cannot be enrolled', function () {
    $this->postJson(route('keyring.authenticators.store', 'password'))->assertNotFound();
    $this->postJson(route('keyring.authenticators.store', 'nope'))->assertNotFound();
});
