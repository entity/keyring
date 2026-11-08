<?php

namespace Keyring\Testing;

use CBOR\ByteStringObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
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

    protected OpenSSLAsymmetricKey $key;

    protected int $counter = 0;

    protected ?string $userHandle = null;

    public function __construct(
        public string $origin = 'http://localhost',
        public bool $userVerification = true,
        public string $aaguid = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
    ) {
        $this->credentialId = random_bytes(32);
        $this->key = openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC]);
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

        openssl_sign($authData.hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256);

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
            'origin' => $origin ?? $this->origin,
            'crossOrigin' => false,
        ], JSON_UNESCAPED_SLASHES);
    }

    protected function authenticatorData(string $rpId, bool $attested): string
    {
        $flags = 0x01 | ($this->userVerification ? 0x04 : 0) | ($attested ? 0x40 : 0);

        $data = hash('sha256', $rpId, true).chr($flags).pack('N', ++$this->counter);

        if ($attested) {
            $data .= $this->aaguid.pack('n', strlen($this->credentialId)).$this->credentialId.$this->publicKey();
        }

        return $data;
    }

    protected function publicKey(): string
    {
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
