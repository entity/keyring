<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Login\Attempt;

/**
 * A login completed and the user was signed in.
 */
class Authenticated
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Attempt $attempt,
    ) {}
}
