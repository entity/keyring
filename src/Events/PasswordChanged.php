<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * The user changed their password. Worth telling them by email.
 */
class PasswordChanged
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
