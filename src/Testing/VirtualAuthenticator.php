<?php

namespace Keyring\Testing;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Keyring\WebAuthn\Ceremonies;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * A software WebAuthn authenticator for tests. It answers the options Keyring
 * gives the browser with real, signed responses, so the full ceremony is
 * exercised without a browser or hardware key.
 *
 *     $key = new VirtualAuthenticator;
 *     $credential = $key->register($response->json('enrollment.options'));
 *     $assertion = $key->assert($response->json('props.challenge.options'));
 */
class VirtualAuthenticator
{
    public readonly string $credentialId;

    protected OpenSSLAsymmetricKey|string $key;

    protected int $counter = 0;

    protected ?string $userHandle = null;

    public function __construct(
        // Where it claims to be. Null: the first origin Keyring accepts, from APP_URL.
        public ?string $origin = null,
        public bool $userVerification = true,
        public string $aaguid = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        public string $algorithm = 'ES256',
        // A passkey that syncs between devices (backup eligible and backed up).
        public bool $synced = false,
    ) {
        $this->credentialId = random_bytes(32);
        $this->key = $algorithm === 'EdDSA'
            ? sodium_crypto_sign_keypair()
            : openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
    }

    /**
     * A key that signs with Ed25519 instead of P-256.
     */
    public static function eddsa(): self
    {
        return new self(algorithm: 'EdDSA');
    }

    /**
     * Answer navigator.credentials.create().
     *
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    public function register(array $options): array
    {
        $this->userHandle = Base64UrlSafe::decodeNoPadding($options['user']['id']);

        $clientData = $this->clientData('webauthn.create', $options['challenge']);

        $authData = $this->authenticatorData($options['rp']['id'], attested: true);

        $attestation = MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return [
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientData),
                'attestationObject' => Base64UrlSafe::encodeUnpadded((string) $attestation),
                'transports' => ['usb'],
            ],
            'clientExtensionResults' => [],
        ];
    }

    /**
     * Answer navigator.credentials.get().
     *
     * @param  array<string, mixed>  $options
     * @return array<string, mixed>
     */
    public function assert(array $options, ?string $origin = null): array
    {
        $clientData = $this->clientData('webauthn.get', $options['challenge'], $origin);
        $authData = $this->authenticatorData($options['rpId'], attested: false);

        $signature = $this->sign($authData.hash('sha256', $clientData, true));

        return [
            'id' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'rawId' => Base64UrlSafe::encodeUnpadded($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64UrlSafe::encodeUnpadded($clientData),
                'authenticatorData' => Base64UrlSafe::encodeUnpadded($authData),
                'signature' => Base64UrlSafe::encodeUnpadded($signature),
                'userHandle' => $this->userHandle === null ? null : Base64UrlSafe::encodeUnpadded($this->userHandle),
            ],
            'clientExtensionResults' => [],
        ];
    }

    /**
     * Pretend the key was cloned: the next response reuses an old counter.
     */
    public function rewindCounter(): static
    {
        $this->counter = max(0, $this->counter - 2);

        return $this;
    }

    protected function clientData(string $type, string $challenge, ?string $origin = null): string
    {
        return json_encode([
            'type' => $type,
            'challenge' => $challenge,
            'origin' => $origin ?? $this->origin ?? app(Ceremonies::class)->origins()[0] ?? 'http://localhost',
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
    }

    protected function authenticatorData(string $rpId, bool $attested): string
    {
        $flags = 0x01 | ($this->userVerification ? 0x04 : 0) | ($this->synced ? 0x08 | 0x10 : 0) | ($attested ? 0x40 : 0);

        $data = hash('sha256', $rpId, true).chr($flags).pack('N', ++$this->counter);

        if ($attested) {
            $data .= $this->aaguid.pack('n', strlen($this->credentialId)).$this->credentialId.$this->publicKey();
        }

        return $data;
    }

    protected function sign(string $data): string
    {
        if (is_string($this->key)) {
            return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($this->key));
        }

        openssl_sign($data, $signature, $this->key, OPENSSL_ALGO_SHA256);

        return $signature;
    }

    protected function publicKey(): string
    {
        if (is_string($this->key)) {
            return (string) MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(1)),     // kty: OKP
                MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-8)),    // alg: EdDSA
                MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(6)),    // crv: Ed25519
                MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create(sodium_crypto_sign_publickey($this->key))),
            ]);
        }

        $ec = openssl_pkey_get_details($this->key)['ec'];

        return (string) MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),        // kty: EC2
            MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7)),       // alg: ES256
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),       // crv: P-256
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create(str_pad($ec['x'], 32, "\0", STR_PAD_LEFT))),
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create(str_pad($ec['y'], 32, "\0", STR_PAD_LEFT))),
        ]);
    }
}
