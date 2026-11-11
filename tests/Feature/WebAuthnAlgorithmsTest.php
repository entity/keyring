<?php

declare(strict_types=1);

use Illuminate\Testing\TestResponse;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\WebAuthn;
use Keyring\KeyringManager;
use Keyring\Models\Authenticator;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\WebAuthn\Ceremonies;
use Webauthn\CredentialRecord;

beforeEach(function () {
    Keyring::factors([Password::class, WebAuthn::passkeys()]);

    $this->user = taylor();
});

/**
 * Add the key as a passkey, and answer how the confirmation went.
 */
function addPasskey(VirtualAuthenticator $key): TestResponse
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL2);

    $options = test()->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');
    $response = test()->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)]);

    test()->post('/logout');

    return $response;
}

/**
 * Sign in with the key alone, and answer how that went.
 */
function signInWithPasskey(VirtualAuthenticator $key): TestResponse
{
    $options = test()->getJson(route('keyring.login.options', 'passkey'))->assertOk()->json('options');

    return test()->postJson(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)]);
}

function offeredAlgorithms(): array
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL2);

    return array_column(test()->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options.pubKeyCredParams'), 'alg');
}

it('offers es256 and ed25519, and leaves rs256 out, unless the app says otherwise', function () {
    expect(offeredAlgorithms())->toBe([-7, -8]);

    config(['keyring.webauthn.algorithms' => ['RS256', 'ES256']]);

    expect(offeredAlgorithms())->toBe([-257, -7]);
});

it('takes an rs256 key once the app lists the algorithm', function () {
    config(['keyring.webauthn.algorithms' => ['ES256', 'EdDSA', 'RS256']]);

    $key = VirtualAuthenticator::rsa();

    addPasskey($key)->assertOk();
    signInWithPasskey($key)->assertOk();

    $this->assertAuthenticatedAs($this->user);
});

it('will not add a key that signs with an algorithm the app has not listed', function (VirtualAuthenticator $key, ?array $algorithms) {
    if ($algorithms !== null) {
        config(['keyring.webauthn.algorithms' => $algorithms]);
    }

    addPasskey($key)->assertUnprocessable();

    expect(Authenticator::count())->toBe(0);
})->with([
    'RS256 by default' => [fn () => VirtualAuthenticator::rsa(), null],
    'Ed25519 when only ES256 is listed' => [fn () => VirtualAuthenticator::eddsa(), ['ES256']],
    'ES256 when only Ed25519 is listed' => [fn () => new VirtualAuthenticator, ['EdDSA']],
]);

it('will not add a key whose algorithm was turned off after it was offered', function () {
    config(['keyring.webauthn.algorithms' => ['ES256', 'RS256']]);

    $key = VirtualAuthenticator::rsa();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');

    config(['keyring.webauthn.algorithms' => ['ES256']]);

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertUnprocessable();

    expect(Authenticator::count())->toBe(0);
});

it('stops signing in with a key once its algorithm is turned off', function (VirtualAuthenticator $key, array $without) {
    config(['keyring.webauthn.algorithms' => ['ES256', 'EdDSA', 'RS256']]);

    addPasskey($key)->assertOk();

    config(['keyring.webauthn.algorithms' => $without]);

    signInWithPasskey($key)->assertUnprocessable();

    $this->assertGuest();
})->with([
    'RS256' => [fn () => VirtualAuthenticator::rsa(), ['ES256', 'EdDSA']],
    'Ed25519' => [fn () => VirtualAuthenticator::eddsa(), ['ES256', 'RS256']],
]);

it('will not add an rsa key shorter than 2048 bits, however low the app sets the floor', function (mixed $floor) {
    config(['keyring.webauthn.algorithms' => ['RS256'], 'keyring.webauthn.minimum_rsa_bits' => $floor]);

    addPasskey(VirtualAuthenticator::rsa(1024))->assertUnprocessable();

    expect(Authenticator::count())->toBe(0);
})->with([2048, 1024, 0, null]);

it('will not add an rsa key shorter than the floor the app raised', function () {
    config(['keyring.webauthn.algorithms' => ['RS256'], 'keyring.webauthn.minimum_rsa_bits' => 3072]);

    addPasskey(VirtualAuthenticator::rsa(2048))->assertUnprocessable();
    addPasskey(VirtualAuthenticator::rsa(3072))->assertOk();

    expect(Authenticator::count())->toBe(1);
});

it('fails a stored rsa key that is too short without relying on php turning warnings into exceptions', function (int $bits, int $floor) {
    config(['keyring.webauthn.algorithms' => ['RS256']]);

    // A key that got in some other way: registration itself would refuse it.
    app()->instance(Ceremonies::class, new class(app(KeyringManager::class)) extends Ceremonies
    {
        public function canVerify(CredentialRecord $record): bool
        {
            return true;
        }
    });

    $key = VirtualAuthenticator::rsa($bits);
    addPasskey($key)->assertOk();

    app()->forgetInstance(Ceremonies::class);
    config(['keyring.webauthn.minimum_rsa_bits' => $floor]);

    // Left to its default, the library only warns about a short key, and
    // with warnings swallowed like this the signature would then pass.
    set_error_handler(fn () => true);

    try {
        signInWithPasskey($key)->assertUnprocessable();
    } finally {
        restore_error_handler();
    }

    $this->assertGuest();
})->with([
    '1024 bits' => [1024, 2048],
    '2048 bits under a floor of 3072' => [2048, 3072],
]);

it('refuses to guess at algorithms when the list is empty or names one it does not know', function (array $algorithms) {
    config(['keyring.webauthn.algorithms' => $algorithms]);

    app(Ceremonies::class)->algorithms();
})->with([
    'empty' => [[]],
    'unknown' => [['ES256', 'PS256']],
])->throws(LogicException::class);
