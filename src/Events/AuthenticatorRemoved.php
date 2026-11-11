<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Models\Authenticator;

/**
 * The user removed an authenticator. Worth telling them by email.
 */
class AuthenticatorRemoved
{
    // Not SerializesModels: the authenticator is already deleted, so a
    // queued listener couldn't fetch it again.
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Authenticator $authenticator,
    ) {}
}
