<?php

declare(strict_types=1);

namespace Keyring\Sso;

/**
 * Who an identity provider says signed in, once everything it sent has been
 * checked. The issuer and subject together name the account at the
 * provider, and are the only pair that does: an email address can be
 * changed, reused or, at some providers, typed in unchecked.
 *
 * emailVerified is only true when the provider vouches for the address
 * itself: "email_verified" set to true in an OpenID Connect ID token, or a
 * primary address GitHub has verified. Anything less, a missing claim or a
 * string "true", reads as unverified, and an unverified address is no proof
 * that the person owns it.
 */
final readonly class Identity
{
    /**
     * @param  list<string>  $amr  how the provider says the user authenticated (RFC 8176), when it says
     * @param  array<string, mixed>  $claims  everything the provider sent about the user, as it sent it
     */
    public function __construct(
        public AuthorizationRequest $request,
        public string $provider,
        public string $issuer,
        public string $subject,
        public ?string $email = null,
        public bool $emailVerified = false,
        public ?string $name = null,
        public ?int $authTime = null,
        public array $amr = [],
        public ?string $acr = null,
        public array $claims = [],
    ) {}
}
