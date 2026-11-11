<?php

use Illuminate\Http\Request;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use ParagonIE\ConstantTime\Base32;

beforeEach(function () {
    $this->user = taylor();
    $this->attempt = Attempt::start(Purpose::Login, $this->user);
});

// Two requests with the same code load the authenticator before either saves.
// Each test verifies with two copies loaded up front to replay that overlap.

it('accepts a totp code once even when two requests race', function () {
    $id = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create()->id;
    [$first, $second] = [Authenticator::find($id), Authenticator::find($id)];
    $request = Request::create('/', 'POST', ['code' => totpCode($first->secret)]);

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

it('keeps recovery codes working after APP_KEY is rotated', function () {
    $id = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create()->id;
    config(['app.previous_keys' => [config('app.key')], 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);

    expect(Keyring::factor('recovery')->verify($this->attempt, Authenticator::find($id), Request::create('/', 'POST', ['code' => 'aaaaa-11111'])))->not->toBeNull();
});

it('makes recovery codes with 128 random bits each, and still takes older shorter ones', function () {
    ['codes' => $codes, 'secret' => $secret] = Keyring::factor('recovery')->generate();

    expect($codes)->each->toMatch('/^[a-z2-7]{4}(-[a-z2-7]{4}){5}-[a-z2-7]{2}$/')
        ->and(array_unique($codes))->toHaveCount(count($codes))
        ->and(array_map(fn (string $code) => strlen(Base32::decodeNoPadding(str_replace('-', '', $code))), $codes))->each->toBe(16);

    $new = Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'recovery', 'secret' => $secret]);
    $typed = strtoupper(str_replace('-', ' ', $codes[0]));

    expect(Keyring::factor('recovery')->verify($this->attempt, $new, Request::create('/', 'POST', ['code' => $typed])))->not->toBeNull();

    $old = Authenticator::factory()->recoveryCodes(['aaaaa-11111'])->for($this->user, 'authenticatable')->create();

    expect(Keyring::factor('recovery')->verify($this->attempt, $old, Request::create('/', 'POST', ['code' => 'aaaaa-11111'])))->not->toBeNull();
});
