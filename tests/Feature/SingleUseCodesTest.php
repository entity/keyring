<?php

use Illuminate\Http\Request;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Factors\SentCodes;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Support\KeyedHash;

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
    $request = Request::create('/', 'POST', ['code' => 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA']);

    expect(Keyring::factor('recovery')->verify($this->attempt, $first, $request))->not->toBeNull()
        ->and(Keyring::factor('recovery')->verify($this->attempt, $second, $request))->toBeNull()
        ->and(Keyring::factor('recovery')->present(Authenticator::find($id))['remaining'])->toBe(2);
});

it('lets one of two requests use up a sent code when both found it unused', function () {
    $codes = app(SentCodes::class);
    $sent = ['hash' => 'the-hash', 'expires_at' => now()->addMinutes(10)->getTimestamp(), 'for' => null];
    $codes->replace('an-attempt', $sent);

    expect($codes->spend('an-attempt', $sent))->toBeTrue()
        ->and($codes->spend('an-attempt', $sent))->toBeFalse()
        ->and($codes->current('an-attempt'))->toBeNull();
});

it('keeps one sent code for each owner, and forgets it once it expires', function () {
    $codes = app(SentCodes::class);
    $codes->replace('an-attempt', ['hash' => 'first', 'expires_at' => now()->addMinutes(10)->getTimestamp(), 'for' => 'a']);
    $codes->replace('an-attempt', ['hash' => 'second', 'expires_at' => now()->addMinutes(10)->getTimestamp(), 'for' => 'b']);

    expect($codes->current('an-attempt'))->toMatchArray(['hash' => 'second', 'for' => 'b'])
        ->and($codes->current('another-attempt'))->toBeNull();

    $this->travel(10)->minutes();
    expect($codes->current('an-attempt'))->not->toBeNull();

    $this->travel(1)->seconds();
    expect($codes->current('an-attempt'))->toBeNull();
});

it('keeps other recovery codes usable when two different codes are used at once', function () {
    $id = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create()->id;
    [$first, $second] = [Authenticator::find($id), Authenticator::find($id)];

    expect(Keyring::factor('recovery')->verify($this->attempt, $first, Request::create('/', 'POST', ['code' => 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA'])))->not->toBeNull()
        ->and(Keyring::factor('recovery')->verify($this->attempt, $second, Request::create('/', 'POST', ['code' => 'BBBB-BBBB-BBBB-BBBB-BBBB-BBBB'])))->not->toBeNull()
        ->and(Keyring::factor('recovery')->present(Authenticator::find($id))['remaining'])->toBe(1);
});

it('keeps recovery codes working after APP_KEY is rotated', function () {
    $id = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create()->id;
    config(['app.previous_keys' => [config('app.key')], 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);

    expect(Keyring::factor('recovery')->verify($this->attempt, Authenticator::find($id), Request::create('/', 'POST', ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa'])))->not->toBeNull();
});

it('makes recovery codes with 120 random bits each', function () {
    ['codes' => $codes, 'secret' => $secret] = Keyring::factor('recovery')->generate();

    expect($codes)->each->toMatch('/^[a-z2-7]{4}(-[a-z2-7]{4}){5}$/')
        ->and(array_unique($codes))->toHaveCount(count($codes));

    $new = Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'recovery', 'secret' => $secret]);
    $typed = strtoupper(str_replace('-', ' ', $codes[0]));

    expect(Keyring::factor('recovery')->verify($this->attempt, $new, Request::create('/', 'POST', ['code' => $typed])))->not->toBeNull();

});

// Before recovery codes had 120 bits they were ten characters, about 52
// bits: far too few to keep as a keyed hash (OWASP ASVS 6.5.2).
it('no longer takes a ten character code, even from a set that holds its hash', function () {
    $old = Authenticator::factory()->for($this->user, 'authenticatable')->create([
        'factor' => 'recovery',
        'secret' => json_encode([KeyedHash::make('aaaaa11111')]),
    ]);

    expect(Keyring::factor('recovery')->verify($this->attempt, $old, Request::create('/', 'POST', ['code' => 'aaaaa-11111'])))->toBeNull()
        ->and(Keyring::factor('recovery')->present($old->fresh())['remaining'])->toBe(1);
});

it('refuses to store a recovery code with fewer than 112 random bits', function (string $code) {
    Keyring::factor('recovery')->secretFor(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa', $code]);
})->with([
    'the old ten characters' => ['aaaaa-11111'],
    'one character short of its own format' => ['aaaa-aaaa-aaaa-aaaa-aaaa-aaa'],
    'one character short of fortify\'s' => ['aBcDeFgHi1-aBcDeFgHi'],
    'a character base32 has no place for' => ['aaaa-aaaa-aaaa-aaaa-aaaa-aaa1'],
    'nothing' => [''],
])->throws(InvalidArgumentException::class, 'Keyring only stores recovery codes with 112 random bits or more');

it('takes a code in fortify\'s format only as it was shown, since its case is part of what makes it long enough', function () {
    $set = Authenticator::factory()->recoveryCodes(['aBcDeFgHi1-JkLmNoPqR2'])->for($this->user, 'authenticatable')->create();
    $verify = fn (string $code) => Keyring::factor('recovery')->verify($this->attempt, Authenticator::find($set->id), Request::create('/', 'POST', ['code' => $code]));

    expect($verify('abcdefghi1-jklmnopqr2'))->toBeNull()
        ->and($verify('ABCDEFGHI1-JKLMNOPQR2'))->toBeNull()
        ->and($verify('aBcDeFgHi1 JkLmNoPqR2'))->not->toBeNull();
});
