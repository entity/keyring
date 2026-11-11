<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * A factor's proof was right, at sign in or step-up. When the policy asks
 * for more than one, each fires this: Authenticated or Confirmed says the
 * whole attempt is done.
 */
class FactorVerified
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Attempt $attempt,
        public readonly Authenticator $authenticator,
        public readonly Verification $verification,
    ) {}
}
