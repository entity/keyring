<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Someone signed in as another user (Keyring::impersonate). The user's own
 * Login and Authenticated events don't fire: they didn't sign in.
 */
class ImpersonationStarted
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $impersonator,
        public readonly Authenticatable $user,
    ) {}
}
