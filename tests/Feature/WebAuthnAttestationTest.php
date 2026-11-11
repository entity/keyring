<?php

use CBOR\ByteStringObject;
use CBOR\Decoder;
use CBOR\MapObject;
use CBOR\StringStream;
use CBOR\TextStringObject;
use Cose\Algorithms;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\TrustsAuthenticators;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\WebAuthn;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Testing\VirtualManufacturer;
use Keyring\Tests\Fixtures\RogueManufacturer;
use Keyring\WebAuthn\Attestation;
use Keyring\WebAuthn\Ceremonies;
use Keyring\WebAuthn\Profile;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Symfony\Component\Uid\Uuid;
use Webauthn\AttestationStatement\AttestationStatement;
use Webauthn\MetadataService\CertificateChain\CertificateToolbox;
use Webauthn\TrustPath\CertificateTrustPath;

const YUBIKEY = '2fc0579f-8113-47ea-b116-bb5a8db9202a';

const TITAN = '42b4fb4a-2866-43b2-9bf7-6c6669c2e5d3';

beforeEach(function () {
    $this->user = taylor();
    $this->maker = new VirtualManufacturer;

    config(['keyring.webauthn.attestation_roots' => [$this->maker->root]]);

    Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()->requireAttestation()]);
});

/**
 * The options the browser gets for a new key.
 *
 * @return array<string, mixed>
 */
function attestationOptions(string $factor = 'security-key'): array
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL2);

    return test()->postJson(route('keyring.authenticators.store', $factor))->assertOk()->json('enrollment.options');
}

/**
 * Try to add a key, or send what's given in place of its answer.
 *
 * @param  (Closure(array<string, mixed>): array<string, mixed>)|null  $answer
 */
function attest(VirtualAuthenticator $key, string $factor = 'security-key', ?Closure $answer = null): TestResponse
{
    $credential = $key->register(attestationOptions($factor));

    return test()->postJson(route('keyring.authenticators.confirm', $factor), ['credential' => $answer ? $answer($credential) : $credential]);
}

/**
 * Change the attestation object a key answered with.
 *
 * @param  array<string, mixed>  $credential
 * @param  Closure(array{fmt: string, attStmt: array<string, mixed>, authData: string}): array{fmt: string, attStmt: array<string, mixed>, authData: string}  $change
 * @return array<string, mixed>
 */
function tamper(array $credential, Closure $change): array
{
    $object = Decoder::create()->decode(StringStream::create(Base64UrlSafe::decodeNoPadding($credential['response']['attestationObject'])));
    $attestation = $change($object->normalize());

    $statement = MapObject::create();

    foreach ($attestation['attStmt'] as $key => $value) {
        $statement->add(TextStringObject::create($key), $object['attStmt'][$key]::class === ByteStringObject::class ? ByteStringObject::create($value) : $object['attStmt'][$key]);
    }

    $credential['response']['attestationObject'] = Base64UrlSafe::encodeUnpadded((string) MapObject::create()
        ->add(TextStringObject::create('fmt'), TextStringObject::create($attestation['fmt']))
        ->add(TextStringObject::create('attStmt'), $statement)
        ->add(TextStringObject::create('authData'), ByteStringObject::create($attestation['authData'])));

    return $credential;
}

/**
 * Refused, and told why: a factor that wants attestation says the key isn't
 * one it takes, since "try again" would never work.
 */
function refused(TestResponse $response, string $message = 'key_not_accepted'): void
{
    $response->assertUnprocessable()->assertJsonValidationErrors(['credential' => __("keyring::keyring.{$message}")]);

    expect(Authenticator::query()->exists())->toBeFalse();
}

it('asks the browser for no attestation unless the factor requires it', function () {
    expect(attestationOptions('passkey')['attestation'])->toBe('none')
        ->and(attestationOptions('security-key')['attestation'])->toBe('direct');

    Keyring::factors([Password::class, WebAuthn::securityKeys()]);

    expect(attestationOptions('security-key')['attestation'])->toBe('none');
});

it('adds a key that does not attest, and keeps no attestation, when the factor does not require it', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys()]);

    attest(new VirtualAuthenticator(userVerification: false))->assertOk();

    $key = Authenticator::query()->sole();

    expect($key->attestation)->toBeNull()
        ->and($key->aaguid)->toBe('00000000-0000-0000-0000-000000000000')
        ->and(app(Ceremonies::class)->record($key->public_key)->attestationType)->toBe('none');
});

it('still takes nothing but "none" attestation when the factor does not require it', function (Closure $key) {
    Keyring::factors([Password::class, WebAuthn::securityKeys()]);

    refused(attest($key($this->maker)), 'invalid');
})->with([
    'packed' => [fn (VirtualManufacturer $maker) => $maker->key(YUBIKEY)],
    'fido-u2f' => [fn (VirtualManufacturer $maker) => $maker->key(format: 'fido-u2f')],
    'self attested' => [fn () => new VirtualAuthenticator()->selfAttested()],
]);

it('adds a key whose attestation chains to a trusted root, and keeps what was checked', function (Closure $maker) {
    $maker = $maker();
    config(['keyring.webauthn.attestation_roots' => [$maker->root]]);

    attest($maker->key(YUBIKEY))->assertOk();

    $key = Authenticator::query()->sole();

    expect($key->factor)->toBe('security-key')
        ->and($key->aaguid)->toBe(YUBIKEY)
        ->and($key->attestation)->toBe('basic')
        ->and(app(Ceremonies::class)->record($key->public_key)->attestationType)->toBe('basic');
})->with([
    'signed by the root' => [fn () => new VirtualManufacturer],
    'signed by an intermediate' => [fn () => new VirtualManufacturer(intermediate: true)],
]);

// A registration a YubiKey really made, against the root Yubico publishes.
it('takes a real key\'s attestation, and refuses it under another maker\'s root', function () {
    $real = json_decode(file_get_contents(__DIR__.'/../Fixtures/attestation/yubikey.json'), true);
    config(['keyring.webauthn.origins' => [$real['origin']], 'keyring.webauthn.relying_party.id' => 'localhost']);

    $ceremonies = app(Ceremonies::class);
    $profile = Profile::securityKeys()->requireAttestation()->allowOnly([$real['aaguid']]);
    $options = $ceremonies->toJson(clone ($ceremonies->creationOptions($this->user, $profile, []), ['challenge' => Base64UrlSafe::decodeNoPadding($real['challenge'])]));

    expect($ceremonies->register(json_encode($real['credential']), $options, $profile))->toBeNull();

    config(['keyring.webauthn.attestation_roots' => [$this->maker->root, $real['root']]]);

    expect($ceremonies->register(json_encode($real['credential']), $options, $profile))
        ->attestationType->toBe('basic')
        ->aaguid->toRfc4122()->toBe($real['aaguid']);

    expect($ceremonies->register(json_encode($real['credential']), $options, $profile->allowOnly([YUBIKEY])))->toBeNull();
});

it('signs in with an attested key afterwards', function () {
    $key = $this->maker->key(YUBIKEY, userVerification: false);
    attest($key)->assertOk();
    $this->post('/logout');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $options = $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.factor', 'security-key')
        ->json('props.challenge.options');

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
});

it('adds an older key that attests as fido-u2f', function () {
    attest($this->maker->key(format: 'fido-u2f', userVerification: false))->assertOk();

    expect(Authenticator::query()->sole())
        ->aaguid->toBe('00000000-0000-0000-0000-000000000000')
        ->attestation->toBe('basic');
});

it('takes a root from a file of pem certificates', function () {
    $file = tempnam(sys_get_temp_dir(), 'keyring');
    file_put_contents($file, new VirtualManufacturer()->root.$this->maker->root);
    config(['keyring.webauthn.attestation_roots' => [$file]]);

    try {
        attest($this->maker->key(YUBIKEY))->assertOk();
    } finally {
        File::delete($file);
    }
});

it('refuses a key that sends no attestation', function () {
    refused(attest(new VirtualAuthenticator(userVerification: false)));
});

it('refuses a key that attests for itself', function (string $aaguid) {
    refused(attest(new VirtualAuthenticator(aaguid: hex2bin(str_replace('-', '', $aaguid)))->selfAttested()));
})->with([
    'with an aaguid' => YUBIKEY,
    'without one' => '00000000-0000-0000-0000-000000000000',
]);

it('refuses a key whose attestation chains to a root that is not trusted', function (string $format) {
    refused(attest(new VirtualManufacturer()->key(format: $format)));
    refused(attest(new VirtualManufacturer(intermediate: true)->key(YUBIKEY)));
})->with(['packed', 'fido-u2f']);

it('refuses a certificate signed by another key\'s certificate instead of an authority', function () {
    $rogue = new RogueManufacturer;
    config(['keyring.webauthn.attestation_roots' => [$rogue->root]]);

    refused(attest($rogue->key(YUBIKEY)));
});

it('refuses a key once its maker\'s certificates have expired', function () {
    $maker = new VirtualManufacturer(days: 30);
    config(['keyring.webauthn.attestation_roots' => [$maker->root]]);
    $key = $maker->key(YUBIKEY);

    $this->travel(31)->days();

    refused(attest($key));
});

it('refuses an attestation that was changed after it was signed', function (string $format, Closure $change) {
    refused(attest($this->maker->key(format: $format), answer: fn (array $credential) => tamper($credential, $change)));
})->with(['packed', 'fido-u2f'])->with([
    'another credential id' => [fn (array $attestation) => [...$attestation, 'authData' => substr_replace($attestation['authData'], ~$attestation['authData'][55], 55, 1)]],
    'another signature' => [fn (array $attestation) => [...$attestation, 'attStmt' => [...$attestation['attStmt'], 'sig' => substr_replace($attestation['attStmt']['sig'], ~$attestation['attStmt']['sig'][20], 20, 1)]]],
]);

it('refuses a statement signed over sha-1, and more certificates than a chain has', function () {
    $aaguid = Uuid::fromString(YUBIKEY);
    $certificates = CertificateToolbox::convertAllDERToPEM($this->maker->certify($aaguid->toBinary())['certificates']);
    $statement = fn (int $algorithm, array $certificates) => AttestationStatement::createBasic('packed', ['alg' => $algorithm, 'sig' => ''], CertificateTrustPath::create($certificates));

    expect(app(Attestation::class))
        ->verifies($statement(Algorithms::COSE_ALGORITHM_ES256, $certificates), $aaguid)->toBeTrue()
        ->verifies($statement(Algorithms::COSE_ALGORITHM_RS1, $certificates), $aaguid)->toBeFalse()
        ->verifies($statement(Algorithms::COSE_ALGORITHM_ES256, array_fill(0, 7, $certificates[0])), $aaguid)->toBeFalse()
        ->verifies($statement(Algorithms::COSE_ALGORITHM_ES256, []), $aaguid)->toBeFalse();
});

it('refuses a genuine certificate that another key signed under', function () {
    $genuine = $this->maker->key(YUBIKEY)->register(attestationOptions());
    $x5c = Decoder::create()->decode(StringStream::create(Base64UrlSafe::decodeNoPadding($genuine['response']['attestationObject'])))->normalize()['attStmt']['x5c'];

    $forged = new VirtualManufacturer()->key(YUBIKEY);

    refused(attest($forged, answer: fn (array $credential) => tamper($credential, fn (array $attestation) => [
        ...$attestation, 'attStmt' => [...$attestation['attStmt'], 'x5c' => $x5c],
    ])));
});

it('refuses an aaguid changed to a model the certificate was not made for', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys()->requireAttestation()->allowOnly([TITAN])]);

    refused(attest($this->maker->key(YUBIKEY), answer: fn (array $credential) => tamper($credential, fn (array $attestation) => [
        ...$attestation, 'authData' => substr_replace($attestation['authData'], hex2bin(str_replace('-', '', TITAN)), 37, 16),
    ])));
});

it('only adds the models on the list', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys()->requireAttestation()->allowOnly([strtoupper(YUBIKEY)])]);

    refused(attest($this->maker->key(TITAN)));
    refused(attest($this->maker->key(format: 'fido-u2f')));

    attest($this->maker->key(YUBIKEY))->assertOk();

    expect(Authenticator::query()->sole()->aaguid)->toBe(YUBIKEY);
});

it('refuses a listed aaguid that nothing vouches for', function (Closure $key) {
    Keyring::factors([Password::class, WebAuthn::securityKeys()->requireAttestation()->allowOnly([YUBIKEY])]);

    refused(attest($key()));
})->with([
    'no attestation' => [fn () => new VirtualAuthenticator(aaguid: hex2bin(str_replace('-', '', YUBIKEY)))],
    'self attested' => [fn () => new VirtualAuthenticator(aaguid: hex2bin(str_replace('-', '', YUBIKEY)))->selfAttested()],
    'another maker' => [fn () => new VirtualManufacturer()->key(YUBIKEY)],
]);

it('adds nothing when the list is empty', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys()->requireAttestation()->allowOnly([])]);

    refused(attest($this->maker->key(YUBIKEY)));
});

it('will not take a list of aaguids without checking attestation', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys()->allowOnly([YUBIKEY])]);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->withoutExceptionHandling();

    expect(fn () => $this->postJson(route('keyring.authenticators.store', 'security-key')))
        ->toThrow(LogicException::class, 'without checking attestation');
});

it('refuses a response for a list of aaguids without attestation, and reports why', function () {
    $ceremonies = app(Ceremonies::class);
    $profile = Profile::securityKeys();
    $options = $ceremonies->creationOptions($this->user, $profile, []);
    Exceptions::fake();

    $result = $ceremonies->register(
        json_encode(new VirtualAuthenticator(aaguid: hex2bin(str_replace('-', '', YUBIKEY)))->register($ceremonies->toBrowser($options))),
        $ceremonies->toJson($options),
        $profile->allowOnly([YUBIKEY]),
    );

    expect($result)->toBeNull();
    Exceptions::assertReported(fn (LogicException $e) => str_contains($e->getMessage(), 'without checking attestation'));
});

it('will not take a list entry that is not an aaguid', function () {
    expect(fn () => WebAuthn::securityKeys()->allowOnly(['YubiKey 5']))->toThrow(InvalidArgumentException::class);
});

it('refuses every key, and reports why, when attestation is required and no root is trusted', function (array $roots, string $message) {
    config(['keyring.webauthn.attestation_roots' => $roots]);
    Exceptions::fake();

    refused(attest($this->maker->key(YUBIKEY)));

    Exceptions::assertReported(fn (LogicException $e) => str_contains($e->getMessage(), $message));
})->with([
    'none listed' => [[], 'no root certificate'],
    'a file that is not there' => [['/nowhere/roots.pem'], 'neither a PEM certificate nor a file'],
    'something that is not a certificate' => [["-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----"], 'could not read a root certificate'],
]);

it('trusts each model as the app\'s own binding says', function () {
    config(['keyring.webauthn.attestation_roots' => []]);
    $maker = $this->maker;

    $this->app->bind(TrustsAuthenticators::class, fn () => new class($maker) implements TrustsAuthenticators
    {
        public function __construct(protected VirtualManufacturer $maker) {}

        public function roots(string $aaguid): array
        {
            // As FIDO metadata lists them: base64, without the PEM armour.
            return $aaguid === YUBIKEY ? [preg_replace('/-----[^-]+-----|\s+/', '', $this->maker->root)] : [];
        }
    });

    refused(attest($this->maker->key(TITAN)));
    refused(attest($this->maker->key(format: 'fido-u2f')));

    attest($this->maker->key(YUBIKEY))->assertOk();
});

it('leaves passkeys alone when only security keys require attestation', function () {
    $passkey = new VirtualAuthenticator(synced: true);
    attest($passkey, 'passkey')->assertOk();

    expect(Authenticator::query()->sole())
        ->factor->toBe('passkey')
        ->attestation->toBeNull();

    $this->post('/logout');
    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $passkey->assert($options)])->assertRedirect('/dashboard');

    // And the passkey profile takes attested responses no more than before.
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    attest($this->maker->key(YUBIKEY), 'passkey')->assertUnprocessable();

    expect(Authenticator::query()->count())->toBe(1);
});

it('still checks the origin and the challenge of an attested key', function () {
    refused(attest(tap($this->maker->key(YUBIKEY), fn (VirtualAuthenticator $key) => $key->origin = 'https://evil.example')));

    $key = $this->maker->key(YUBIKEY);
    $stale = $key->register(attestationOptions());

    refused(attest($key, answer: fn () => $stale));
});

it('makes an attested key with the factory', function () {
    $key = Authenticator::factory()->securityKey()->attested(YUBIKEY)->for($this->user, 'authenticatable')->create();

    expect($key->refresh())->aaguid->toBe(YUBIKEY)->attestation->toBe('basic');
});

// NIST SP 800-63B-4, Sec. 2.3: AAL3 takes a key that can't be exported, and
// its own activation or a password beside it. Only attestation says what
// kind of authenticator a key is.
describe('aal3', function () {
    beforeEach(function () {
        Route::middleware(['web', 'auth', 'keyring:aal3'])->get('/vault', fn () => 'vault');
        Route::middleware(['web', 'auth', 'keyring:aal2,device-bound'])->get('/keys-only', fn () => 'keys only');
        config(['keyring.enrollment_url' => '/settings/security']);
    });

    /**
     * Sign in with the password, then the security key.
     */
    function signInWithKey(VirtualAuthenticator $key): void
    {
        test()->post('/logout');
        test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $options = test()->inertia()->get(route('keyring.login.challenge', 'security-key'))->json('props.challenge.options');

        test()->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');
    }

    it('doesn\'t reach aal3 with a key added before the factor asked for attestation', function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()]);
        $key = new VirtualAuthenticator(userVerification: false);
        attest($key)->assertOk();

        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()->requireAttestation()]);
        signInWithKey($key);

        expect(Authenticator::query()->sole()->attestation)->toBeNull()
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);

        // With no key that could reach it, confirming again can't help.
        $this->get('/vault')->assertRedirect('/settings/security');
        $this->get('/keys-only')->assertOk();
    });

    it('doesn\'t reach aal3 once the factor stops asking for attestation', function () {
        $key = $this->maker->key(YUBIKEY, userVerification: false);
        attest($key)->assertOk();

        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()]);
        signInWithKey($key);

        expect(Authenticator::query()->sole()->attestation)->toBe('basic')
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
    });

    it('reaches aal3 with an attested key that verified the user itself', function () {
        $key = $this->maker->key(YUBIKEY);
        attest($key)->assertOk();
        signInWithKey($key);

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
        $this->get('/vault')->assertOk();
    });

    it('doesn\'t take a synced passkey\'s user verification for the attested key\'s', function () {
        $passkey = new VirtualAuthenticator(synced: true);
        attest($passkey, 'passkey')->assertOk();
        $key = $this->maker->key(YUBIKEY, userVerification: false);
        attest($key)->assertOk();
        $this->post('/logout');

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $passkey->assert($options)])->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);

        // The key is asked for first, and touching it isn't enough: the
        // passkey's fingerprint says nothing about who touched the key.
        $this->get('/vault')->assertRedirect(route('keyring.confirm.challenge'));
        $options = $this->inertia()->get(route('keyring.confirm.challenge'))
            ->assertJsonPath('props.factor', 'security-key')
            ->json('props.challenge.options');

        $this->post(route('keyring.confirm.verify', 'security-key'), ['credential' => $key->assert($options)])
            ->assertRedirect(route('keyring.confirm.challenge'));

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);

        $this->inertia()->get(route('keyring.confirm.challenge'))
            ->assertJsonPath('props.factor', 'password')
            ->assertJsonPath('props.alternatives', []);
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/vault');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
        $this->get('/vault')->assertOk();
    });

    it('lets a route ask for a key that stays on its device without asking who made it', function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()]);
        $passkey = new VirtualAuthenticator(synced: true);
        attest($passkey, 'passkey')->assertOk();
        $this->post('/logout');

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $passkey->assert($options)]);

        // AAL2 already, and no such key on the account to step up with.
        $this->get('/keys-only')->assertRedirect('/settings/security');

        $key = new VirtualAuthenticator(userVerification: false);
        attest($key)->assertOk();
        signInWithKey($key);

        $this->get('/keys-only')->assertOk();
        $this->get('/vault')->assertRedirect('/settings/security');
    });
});
