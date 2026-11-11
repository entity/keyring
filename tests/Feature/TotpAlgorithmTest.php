<?php

use Illuminate\Http\Request;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function () {
    $this->user = taylor();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
});

/**
 * Set the authenticator app factor up with a digest, as an app would.
 */
function totpWith(string $algorithm): void
{
    Keyring::factors([Password::class, fn ($app) => $app->make(Totp::class, ['algorithm' => $algorithm]), RecoveryCodes::class]);
}

/**
 * Whether the factor takes the code as a second factor for the authenticator.
 */
function totpAccepts(Authenticator $authenticator, string $code): bool
{
    return Keyring::factor('totp')->verify(Attempt::start(Purpose::Login, test()->user), $authenticator, Request::create('/', 'POST', ['code' => $code])) !== null;
}

it('makes sha1 codes unless told otherwise, and says so in the url the app scans', function () {
    $enrollment = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment');

    parse_str((string) parse_url($enrollment['url'], PHP_URL_QUERY), $query);

    expect($query['algorithm'])->toBe('SHA1')
        ->and($enrollment['algorithm'])->toBe('SHA1');

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => $this->totpCode($enrollment['secret'])])->assertOk();

    expect(Authenticator::where('factor', 'totp')->sole()->meta('algorithm'))->toBe('sha1');
});

it('can be set up with a stronger digest, which the url and the qr code then name', function (string $algorithm) {
    totpWith($algorithm);

    $enrollment = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment');

    parse_str((string) parse_url($enrollment['url'], PHP_URL_QUERY), $query);

    expect($query['algorithm'])->toBe(strtoupper($algorithm))
        ->and($enrollment['algorithm'])->toBe(strtoupper($algorithm))
        ->and($enrollment['qr'])->toStartWith('<svg');

    // What an app that ignored the digest would show.
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => $this->totpCode($enrollment['secret'])])->assertUnprocessable();

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => $this->totpCode($enrollment['secret'], algorithm: $algorithm)])->assertOk();

    $totp = Authenticator::where('factor', 'totp')->sole();

    expect($totp->meta('algorithm'))->toBe($algorithm);

    $this->travel(30)->seconds();

    expect(totpAccepts($totp, $this->totpCode((string) $totp->secret)))->toBeFalse()
        ->and(totpAccepts($totp, $this->totpCode($totp)))->toBeTrue();
})->with(['sha256', 'sha512']);

it('keeps verifying an authenticator under the digest it was set up with when the setting changes', function (string $from, string $to) {
    totpWith($from);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => $this->totpCode($secret, algorithm: $from)])->assertOk();

    totpWith($to);

    $totp = Authenticator::where('factor', 'totp')->sole();

    $this->travel(30)->seconds();

    expect(totpAccepts($totp, $this->totpCode($secret, algorithm: $to)))->toBeFalse()
        ->and(totpAccepts($totp, $this->totpCode($secret, algorithm: $from)))->toBeTrue();
})->with([
    'sha1 to sha256' => ['sha1', 'sha256'],
    'sha256 to sha1' => ['sha256', 'sha1'],
    'sha512 to sha256' => ['sha512', 'sha256'],
]);

it('finishes an enrollment under the digest its qr code named when the setting changes meanwhile', function () {
    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');

    totpWith('sha256');

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => $this->totpCode($secret)])->assertOk();

    expect(Authenticator::where('factor', 'totp')->sole()->meta('algorithm'))->toBe('sha1');
});

it('takes an authenticator stored without a digest for sha1, whatever the setting', function () {
    totpWith('sha256');

    // As keyring:import brings one over from Fortify.
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    expect($totp->meta('algorithm'))->toBeNull()
        ->and(totpAccepts($totp, $this->totpCode((string) $totp->secret, algorithm: 'sha256')))->toBeFalse()
        ->and(totpAccepts($totp, $this->totpCode((string) $totp->secret)))->toBeTrue();
});

it('fails an authenticator whose stored digest is not one it knows', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['meta' => ['algorithm' => 'md5']]);

    expect(totpAccepts($totp, $this->totpCode((string) $totp->secret)))->toBeFalse();
});

it('will not be set up with a digest totp does not have', function () {
    new Totp(new Google2FA, algorithm: 'md5');
})->throws(InvalidArgumentException::class);

it('does not leave one request\'s digest on the engine the next one uses', function () {
    $engine = new Google2FA;
    $factor = new Totp($engine, algorithm: 'sha512');

    $factor->beginEnrollment($this->user, Request::create('/', 'POST'));

    expect($engine->getAlgorithm())->toBe('sha1');
});
