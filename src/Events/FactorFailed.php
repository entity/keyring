<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Illuminate\Queue\SerializesModels;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Factors\Password;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * A factor failed to verify. The attempt is null when the user wasn't identified.
 */
class FactorFailed
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly ?Attempt $attempt,
        public readonly ?Authenticator $authenticator,
        public readonly string $factor,
        public readonly Request $request,
    ) {}

    /**
     * The first step of the login this failed in, when it had already
     * passed: the password, or another proof of the same kind, such as an
     * identity provider. Null for a first step that failed, and outside a
     * login.
     */
    public function firstFactor(): ?Verification
    {
        return $this->attempt?->purpose === Purpose::Login
            ? array_find($this->attempt->verifications, fn (Verification $verification) => in_array(Category::Knowledge, $verification->categories, true))
            : null;
    }

    /**
     * Whether this was a later step of a login whose first step passed,
     * which suggests someone else can get that far.
     */
    public function afterFirstFactor(): bool
    {
        return $this->firstFactor() !== null;
    }

    /**
     * Whether that first step was the password, which suggests the password
     * is known to someone. False after an identity provider: the password
     * may never have been used.
     */
    public function afterPassword(): bool
    {
        return $this->firstFactor()?->factor === Password::KEY;
    }
}
