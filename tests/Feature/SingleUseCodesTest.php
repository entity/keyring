<?php

use Illuminate\Http\Request;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function () {
    $this->user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    $this->attempt = Attempt::start(Purpose::Login, $this->user);
});

// Two requests with the same code load the authenticator before either saves.
// Each test verifies with two copies loaded up front to replay that overlap.

it('accepts a totp code once even when two requests race', function () {
    $id = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create()->id;
    [$first, $second] = [Authenticator::find($id), Authenticator::find($id)];
    $request = Request::create('/', 'POST', ['code' => app(Google2FA::class)->getCurrentOtp($first->secret)]);

    expect(Keyring::factor('totp')->verify($this->attempt, $first, $request))->not->toBeNull()
        ->and(Keyring::factor('totp')->verify($this->attempt, $second, $request))->toBeNull();
});

it('accepts a recovery code once even when two requests race', function () {
    $id = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create()->id;
    [$first, $second] = [Authenticator::find($id), Authenticator::find($id)];
    $request = Request::create('/', 'POST', ['code' => 'AAAAA-11111']);

    expect(Keyring::factor('recovery')->verify($this->attempt, $first, $request))->not->toBeNull()
        ->and(Keyring::factor('recovery')->verify($this->attempt, $second, $request))->toBeNull()
        ->and(Keyring::factor('recovery')->present(Authenticator::find($id))['remaining'])->toBe(2);
});

it('keeps other recovery codes usable when two different codes are used at once', function () {
    $id = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create()->id;
    [$first, $second] = [Authenticator::find($id), Authenticator::find($id)];

    expect(Keyring::factor('recovery')->verify($this->attempt, $first, Request::create('/', 'POST', ['code' => 'AAAAA-11111'])))->not->toBeNull()
        ->and(Keyring::factor('recovery')->verify($this->attempt, $second, Request::create('/', 'POST', ['code' => 'BBBBB-22222'])))->not->toBeNull()
        ->and(Keyring::factor('recovery')->present(Authenticator::find($id))['remaining'])->toBe(1);
});
