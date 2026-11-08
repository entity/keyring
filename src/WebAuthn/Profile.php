<?php

namespace Keyring\WebAuthn;

use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;

/**
 * How a WebAuthn factor asks for credentials. Passkeys and security keys use
 * the same ceremony with different settings.
 */
final readonly class Profile
{
    public function __construct(
        public string $key,
        public string $residentKey,
        public string $userVerification,
        public bool $primary,
        public ?string $attachment = null,
        public string $attestation = PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        public int $priority = 90,
    ) {}

    /**
     * Discoverable, user-verified credentials that can sign in on their own.
     */
    public static function passkeys(): self
    {
        return new self(
            key: 'passkey',
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
            key: 'security-key',
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

    public function requiresUserVerification(): bool
    {
        return $this->userVerification === AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED;
    }
}
