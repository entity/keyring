<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * Sessions were signed out, e.g. "sign out everywhere else".
 */
class SessionsRevoked
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly int $count,
    ) {}
}
