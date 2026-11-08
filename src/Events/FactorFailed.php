<?php

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * A factor failed to verify. The attempt is null when the user wasn't identified.
 */
class FactorFailed
{
    use Dispatchable;

    public function __construct(
        public readonly ?Attempt $attempt,
        public readonly ?Authenticator $authenticator,
        public readonly string $factor,
        public readonly Request $request,
    ) {}

    /**
     * Whether this was the second step of a login that already got the
     * password right, which suggests the password is known to someone.
     */
    public function afterPassword(): bool
    {
        return $this->attempt?->purpose === Purpose::Login
            && array_any($this->attempt->verifications, fn (Verification $verification) => in_array(Category::Knowledge, $verification->categories, true));
    }
}
