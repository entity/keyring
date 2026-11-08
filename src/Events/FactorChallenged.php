<?php

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;

/**
 * The challenge page was shown for an authenticator.
 */
class FactorChallenged
{
    use Dispatchable;

    public function __construct(
        public readonly Attempt $attempt,
        public readonly Authenticator $authenticator,
    ) {}
}
