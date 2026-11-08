<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Login\Attempt;

/**
 * A step-up confirmation completed.
 */
class Confirmed
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Attempt $attempt,
    ) {}
}
