<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Models\Authenticator;

/**
 * The user added an authenticator. Worth telling them by email (OWASP).
 */
class AuthenticatorAdded
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Authenticator $authenticator,
    ) {}
}
