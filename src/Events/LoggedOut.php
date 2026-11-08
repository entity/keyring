<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * The user signed out.
 */
class LoggedOut
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
