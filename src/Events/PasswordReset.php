<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * The password was reset from a reset link. Every session was signed out.
 */
class PasswordReset
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
