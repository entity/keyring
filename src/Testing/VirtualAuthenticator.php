<?php

namespace Keyring\Testing;

use CBOR\ByteStringObject;
use CBOR\ListObject;
use CBOR\MapItem;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Keyring\WebAuthn\Ceremonies;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

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

    /** @var OpenSSLAsymmetricKey|non-empty-string */
    protected OpenSSLAsymmetricKey|string $key;

    protected int $counter = 0;

    protected ?string $userHandle = null;

    /**
     * How it attests when registered: "none", "self", "packed" or "fido-u2f".
     */
    protected string $attestation = 'none';

    /**
     * Its maker's certificate for the model, and the key that signs with it.
     *
     * @var array{key: OpenSSLAsymmetricKey, certificates: list<string>}|null
     */
    protected ?array $certified = null;

    public function __construct(
        // Where it claims to be. Null: the first origin Keyring accepts, from APP_URL.
        public ?string $origin = null,
        public bool $userVerification = true,
        public string $aaguid = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        public string $algorithm = 'ES256',
        // A passkey that syncs between devices (backup eligible and backed up).
        public bool $synced = false,
        // How long an RS256 key is.
        public int $bits = 2048,
        // Whether a passkey that syncs has been backed up yet. Null: it has.
        public ?bool $backedUp = null,
    ) {
        $this->credentialId = random_bytes(32);
        $this->key = match ($algorithm) {
            'EdDSA' => sodium_crypto_sign_keypair(),
            'RS256' => openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA])
                ?: throw new RuntimeException('OpenSSL could not make an RSA key pair.'),
            default => openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC])
                ?: throw new RuntimeException('OpenSSL could not make a P-256 key pair.'),
        };
    }

    /**
     * A key that signs with Ed25519 instead of P-256.
     */
    public static function eddsa(): self
    {
        return new self(algorithm: 'EdDSA');
    }

    /**
     * A key that signs with RS256, as Windows Hello does where it has
     * nothing else. Keyring only takes one when the app lists RS256.
     */
    public static function rsa(int $bits = 2048): self
    {
        return new self(algorithm: 'RS256', bits: $bits);
    }

    /**
     * Attest registrations as a key this maker made would, in the "packed"
     * format of FIDO2 keys or the "fido-u2f" one of older keys.
     */
    public function attestedBy(VirtualManufacturer $maker, string $format = 'packed'): static
    {
        // A U2F key has no AAGUID.
        if ($format === 'fido-u2f') {
            $this->aaguid = str_repeat("\0", 16);
        }

        $this->attestation = $format;
        $this->certified = $maker->certify($this->aaguid);

        return $this;
    }

    /**
     * Attest registrations with the key's own key pair, which says nothing
     * about who made it.
     */
    public function selfAttested(): static
    {
        $this->attestation = 'self';

        return $this;
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
            ->add(TextStringObject::create('fmt'), TextStringObject::create($this->attestation === 'self' ? 'packed' : $this->attestation))
            ->add(TextStringObject::create('attStmt'), $this->attestationStatement($options['rp']['id'], $authData, hash('sha256', $clientData, true)))
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
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    protected function authenticatorData(string $rpId, bool $attested): string
    {
        $flags = 0x01 | ($this->userVerification ? 0x04 : 0) | ($this->synced ? 0x08 : 0) | ($this->synced && ($this->backedUp ?? true) ? 0x10 : 0) | ($attested ? 0x40 : 0);

        $data = hash('sha256', $rpId, true).chr($flags).pack('N', ++$this->counter);

        if ($attested) {
            $data .= $this->aaguid.pack('n', strlen($this->credentialId)).$this->credentialId.$this->publicKey();
        }

        return $data;
    }

    /**
     * What vouches for the new credential, signed by the key itself or with
     * its maker's certificate.
     */
    protected function attestationStatement(string $rpId, string $authData, string $clientDataHash): MapObject
    {
        $statement = MapObject::create();

        if ($this->attestation === 'none') {
            return $statement;
        }

        if ($this->attestation !== 'fido-u2f') {
            $statement->add(TextStringObject::create('alg'), NegativeIntegerObject::create($this->attestation === 'self' ? $this->identifier() : -7));
        }

        $statement->add(TextStringObject::create('sig'), ByteStringObject::create(match ($this->attestation) {
            'self' => $this->sign($authData.$clientDataHash),
            'fido-u2f' => $this->sign("\0".hash('sha256', $rpId, true).$clientDataHash.$this->credentialId."\x04".implode('', $this->point()), $this->certified['key'] ?? null),
            default => $this->sign($authData.$clientDataHash, $this->certified['key'] ?? null),
        }));

        if ($this->attestation !== 'self') {
            $statement->add(TextStringObject::create('x5c'), ListObject::create(array_map(ByteStringObject::create(...), $this->certified['certificates'] ?? [])));
        }

        return $statement;
    }

    /**
     * Sign with the credential's key, or with the one given.
     */
    protected function sign(string $data, ?OpenSSLAsymmetricKey $key = null): string
    {
        $key ??= $this->key;

        if (is_string($key)) {
            return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($key));
        }

        openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256);

        return $signature;
    }

    /**
     * The COSE number of the algorithm the key signs with.
     */
    protected function identifier(): int
    {
        return match ($this->algorithm) {
            'EdDSA' => -8,
            'RS256' => -257,
            default => -7,
        };
    }

    protected function publicKey(): string
    {
        if ($this->algorithm === 'RS256' && ! is_string($this->key)) {
            $rsa = (openssl_pkey_get_details($this->key) ?: throw new RuntimeException('OpenSSL could not read the key pair.'))['rsa'];

            return (string) MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(3)),     // kty: RSA
                MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-257)),  // alg: RS256
                MapItem::create(NegativeIntegerObject::create(-1), ByteStringObject::create($rsa['n'])),
                MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create($rsa['e'])),
            ]);
        }

        if (is_string($this->key)) {
            return (string) MapObject::create([
                MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(1)),     // kty: OKP
                MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-8)),    // alg: EdDSA
                MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(6)),    // crv: Ed25519
                MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create(sodium_crypto_sign_publickey($this->key))),
            ]);
        }

        [$x, $y] = $this->point();

        return (string) MapObject::create([
            MapItem::create(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2)),        // kty: EC2
            MapItem::create(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7)),       // alg: ES256
            MapItem::create(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1)),       // crv: P-256
            MapItem::create(NegativeIntegerObject::create(-2), ByteStringObject::create($x)),
            MapItem::create(NegativeIntegerObject::create(-3), ByteStringObject::create($y)),
        ]);
    }

    /**
     * The P-256 public key's coordinates.
     *
     * @return array{string, string}
     */
    protected function point(): array
    {
        if (is_string($this->key) || $this->algorithm === 'RS256') {
            throw new RuntimeException('Only a P-256 key has a point on the curve.');
        }

        $ec = (openssl_pkey_get_details($this->key) ?: throw new RuntimeException('OpenSSL could not read the key pair.'))['ec'];

        return [str_pad($ec['x'], 32, "\0", STR_PAD_LEFT), str_pad($ec['y'], 32, "\0", STR_PAD_LEFT)];
    }
}
