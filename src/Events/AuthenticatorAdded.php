<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Models\Authenticator;

/**
 * The user added an authenticator. Worth telling them by email.
 */
class AuthenticatorAdded
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Authenticator $authenticator,
    ) {}
}
