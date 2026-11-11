<?php

declare(strict_types=1);

namespace Keyring\WebAuthn;

use Illuminate\Support\Str;
use InvalidArgumentException;
use Webauthn\AuthenticatorSelectionCriteria;

/**
 * How a WebAuthn factor asks for credentials. Passkeys and security keys use
 * the same ceremony with different settings.
 */
final readonly class Profile
{
    public const string PASSKEY = 'passkey';

    public const string SECURITY_KEY = 'security-key';

    /**
     * @param  list<string>|null  $aaguids  the only models to enroll, or null for any
     */
    public function __construct(
        public string $key,
        public string $residentKey,
        public string $userVerification,
        public bool $primary,
        public ?string $attachment = null,
        public int $priority = 90,
        public bool $attestation = false,
        public ?array $aaguids = null,
    ) {}

    /**
     * Discoverable, user-verified credentials that can sign in on their own.
     */
    public static function passkeys(): self
    {
        return new self(
            key: self::PASSKEY,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            primary: true,
            priority: 100,
        );
    }

    /**
     * Hardware keys used as a second factor. User verification is preferred,
     * and only counted when the key actually performs it.
     */
    public static function securityKeys(): self
    {
        return new self(
            key: self::SECURITY_KEY,
            residentKey: AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_DISCOURAGED,
            userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            primary: false,
            attachment: AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
            priority: 90,
        );
    }

    #[\NoDiscard]
    public function as(string $key): self
    {
        return clone ($this, ['key' => $key]);
    }

    #[\NoDiscard]
    public function requireUserVerification(bool $required = true): self
    {
        return clone ($this, [
            'userVerification' => $required
                ? AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED
                : AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
        ]);
    }

    /**
     * Only enroll keys whose maker vouches for them: the attestation has to
     * chain to a root certificate the app trusts. Passkeys that sync rarely
     * carry one, so this is for hardware keys.
     */
    #[\NoDiscard]
    public function requireAttestation(bool $required = true): self
    {
        return clone ($this, ['attestation' => $required]);
    }

    /**
     * Only enroll these models, by AAGUID. It needs requireAttestation() too:
     * an AAGUID nobody vouches for is just what the key says about itself.
     * An empty list enrolls none.
     *
     * @param  list<string>  $aaguids
     */
    #[\NoDiscard]
    public function allowOnly(array $aaguids): self
    {
        // A misspelt one would otherwise just never match.
        if (! array_all($aaguids, fn (mixed $aaguid) => Str::isUuid($aaguid))) {
            throw new InvalidArgumentException('An AAGUID is a UUID, such as 2fc0579f-8113-47ea-b116-bb5a8db9202a.');
        }

        return clone ($this, ['aaguids' => array_map(strtolower(...), $aaguids)]);
    }

    public function requiresUserVerification(): bool
    {
        return $this->userVerification === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
    }
}
