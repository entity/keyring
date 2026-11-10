<?php

namespace Keyring\Contracts;

use Illuminate\Http\Request;
use Keyring\Models\Authenticator;

/**
 * A factor that can start a login by identifying the user, like a password
 * (via their email) or a discoverable passkey (via its credential).
 */
interface PrimaryFactor extends Factor
{
    /**
     * Whether this factor, as configured, can start a login. WebAuthn is
     * primary for passkeys, but security keys only ever come second.
     */
    public function startsLogin(): bool;

    /**
     * Whether verify() checks a proof of its own, so the factor can also
     * answer a challenge or a step-up, which never call identify(). Return
     * false when the proof is who identify() found, like a social login:
     * that factor can only start a login.
     */
    public function answersChallenges(): bool;

    /**
     * Find the authenticator the request is aimed at.
     *
     * Implementations must take the same time whether or not a user is found,
     * so the response doesn't reveal which accounts exist.
     */
    public function identify(Request $request): ?Authenticator;

    /**
     * Validation rules for the fields used to identify the user.
     *
     * @return array<string, mixed>
     */
    public function identificationRules(): array;
}
