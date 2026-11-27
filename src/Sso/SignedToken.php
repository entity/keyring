<?php

declare(strict_types=1);

namespace Keyring\Sso;

use Cose\Key\Ec2Key;
use Cose\Key\Key;
use Cose\Key\RsaKey;
use Cose\Key\RsaKeyValidator;
use InvalidArgumentException;
use JsonException;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Throwable;

/**
 * A JSON Web Signature in compact form (RFC 7515), as an ID token is sent.
 * Parsing one checks nothing but its shape: what it claims is only worth
 * reading once signedBy() says one of the provider's keys signed it.
 *
 * Only asymmetric algorithms are taken, so the key that checks a signature
 * can never make one. "none" signs nothing, and with HS256 the provider's
 * public key would be the secret: an attacker who has it (everyone does)
 * could sign anything. The algorithm the token names must also be the one
 * its key is for, so a token can't pick how its own key is read.
 */
final readonly class SignedToken
{
    /**
     * RS256 is what OpenID Connect requires every provider to offer, ES256
     * and EdDSA (or Ed25519, as RFC 9864 renames it) are what newer ones
     * sign with, and PS256 is RS256's successor.
     */
    public const array ALGORITHMS = ['RS256', 'PS256', 'ES256', 'EdDSA', 'Ed25519'];

    /**
     * Far longer than any ID token, even one carrying a large groups claim,
     * and short enough that a hostile one can't cost much to look at. It
     * comes back from the configured token endpoint, not the browser.
     */
    protected const int LONGEST = 64 * 1024;

    /**
     * The shortest RSA key a signature is checked with. It's its own floor,
     * not the one passkeys have (keyring.webauthn.minimum_rsa_bits): Google
     * and Microsoft sign with 2048-bit keys, so raising that one for
     * passkeys mustn't refuse every token they send.
     */
    public const int SHORTEST_RSA_KEY = 2048;

    /**
     * @param  array<string, mixed>  $header
     * @param  array<string, mixed>  $claims
     */
    private function __construct(
        public array $header,
        public array $claims,
        private string $signed,
        private string $signature,
    ) {}

    /**
     * @throws InvalidArgumentException when it isn't a compact JWS with JSON objects inside
     */
    public static function parse(string $token): self
    {
        if (strlen($token) > self::LONGEST) {
            throw new InvalidArgumentException('It is longer than '.(self::LONGEST / 1024).' KiB.');
        }

        if (preg_match('/^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/D', $token, $parts) !== 1) {
            throw new InvalidArgumentException('It is not a signed JWT in compact form.');
        }

        $header = self::object($parts[1]);

        // Extensions that must be understood: Keyring understands none.
        if (array_key_exists('crit', $header)) {
            throw new InvalidArgumentException('It names critical header parameters.');
        }

        return new self($header, self::object($parts[2]), $parts[1].'.'.$parts[2], self::decode($parts[3]));
    }

    public function algorithm(): ?string
    {
        return is_string($this->header['alg'] ?? null) ? $this->header['alg'] : null;
    }

    public function keyId(): ?string
    {
        return is_string($this->header['kid'] ?? null) ? $this->header['kid'] : null;
    }

    /**
     * Whether this JSON Web Key (RFC 7517) signed the token, with an
     * algorithm Keyring takes and the key is for. A key that names its
     * use, operations or algorithm has to allow this one, an EC key has to
     * be on P-256 and an OKP key Ed25519, and an RSA key has to be at least
     * SHORTEST_RSA_KEY bits long.
     *
     * @param  array<array-key, mixed>  $jwk
     */
    public function signedBy(array $jwk): bool
    {
        $algorithm = $this->algorithm();

        if (! in_array($algorithm, self::ALGORITHMS, true)
            || (isset($jwk['alg']) && $jwk['alg'] !== $algorithm)
            || (isset($jwk['use']) && $jwk['use'] !== 'sig')
            || (isset($jwk['key_ops']) && (! is_array($jwk['key_ops']) || ! in_array('verify', $jwk['key_ops'], true)))) {
            return false;
        }

        // A key that isn't what it says, or holds a coordinate that isn't
        // base64url, is no key at all.
        try {
            return match ($algorithm) {
                'RS256', 'PS256' => $this->verifyRsa($jwk, $algorithm === 'PS256' ? OPENSSL_PKCS1_PSS_PADDING : OPENSSL_PKCS1_PADDING),
                'ES256' => $this->verifyEc($jwk),
                default => $this->verifyEd25519($jwk),
            };
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * @param  array<array-key, mixed>  $jwk
     */
    private function verifyRsa(array $jwk, int $padding): bool
    {
        if (($jwk['kty'] ?? null) !== 'RSA' || ! is_string($jwk['n'] ?? null) || ! is_string($jwk['e'] ?? null)) {
            return false;
        }

        $key = RsaKey::create([Key::TYPE => Key::TYPE_RSA, RsaKey::DATA_N => self::decode($jwk['n']), RsaKey::DATA_E => self::decode($jwk['e'])]);

        if (! RsaKeyValidator::create(self::SHORTEST_RSA_KEY)->isValid($key)) {
            return false;
        }

        return $this->verifyOpenSsl($key->asPem(), $this->signature, $padding);
    }

    /**
     * @param  array<array-key, mixed>  $jwk
     */
    private function verifyEc(array $jwk): bool
    {
        if (($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256' || ! is_string($jwk['x'] ?? null) || ! is_string($jwk['y'] ?? null)) {
            return false;
        }

        $key = Ec2Key::create([Key::TYPE => Key::TYPE_EC2, Ec2Key::DATA_CURVE => Ec2Key::CURVE_P256, Ec2Key::DATA_X => self::decode($jwk['x']), Ec2Key::DATA_Y => self::decode($jwk['y'])]);

        $signature = $this->derSignature($this->signature);

        return $signature !== null && $this->verifyOpenSsl($key->asPEM(), $signature);
    }

    /**
     * @param  array<array-key, mixed>  $jwk
     */
    private function verifyEd25519(array $jwk): bool
    {
        if (($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519' || ! is_string($jwk['x'] ?? null)) {
            return false;
        }

        $key = self::decode($jwk['x']);

        return strlen($key) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
            && strlen($this->signature) === SODIUM_CRYPTO_SIGN_BYTES
            && sodium_crypto_sign_verify_detached($this->signature, $this->signed, $key);
    }

    /**
     * A point that isn't on the curve makes a PEM OpenSSL won't load, which
     * is refused here rather than warned about by openssl_verify(). Padding
     * is only for RSA: 0 is OpenSSL's default, which other keys need.
     */
    private function verifyOpenSsl(string $pem, string $signature, int $padding = 0): bool
    {
        $key = openssl_pkey_get_public($pem);

        return $key !== false && openssl_verify($this->signed, $signature, $key, OPENSSL_ALGO_SHA256, $padding) === 1;
    }

    /**
     * JWS signs ES256 as r and s side by side, 32 bytes each (RFC 7518,
     * Sec. 3.4). OpenSSL wants them as a DER sequence of two integers.
     * Null when either is zero, which no signature is.
     */
    private function derSignature(string $signature): ?string
    {
        if (strlen($signature) !== 64) {
            return null;
        }

        $integers = '';

        foreach (str_split($signature, 32) as $half) {
            $integer = ltrim($half, "\0");

            if ($integer === '') {
                return null;
            }

            // A high first bit would read as negative.
            if (ord($integer[0]) > 0x7F) {
                $integer = "\0".$integer;
            }

            $integers .= pack('CC', 0x02, strlen($integer)).$integer;
        }

        return pack('CC', 0x30, strlen($integers)).$integers;
    }

    /**
     * @return array<string, mixed>
     */
    private static function object(string $segment): array
    {
        try {
            $value = json_decode(self::decode($segment), true, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidArgumentException('It does not hold JSON.');
        }

        if (! is_array($value) || array_is_list($value)) {
            throw new InvalidArgumentException('It does not hold a JSON object.');
        }

        return $value;
    }

    private static function decode(string $value): string
    {
        try {
            return Base64UrlSafe::decodeNoPadding($value);
        } catch (Throwable) {
            throw new InvalidArgumentException('It is not base64url.');
        }
    }
}
