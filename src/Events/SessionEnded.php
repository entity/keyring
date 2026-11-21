<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Keyring signed a session out on its own: it was revoked, timed out, a
 * risk response ended it, or its "remember me" cookie had already been used
 * (RememberMeReused). Signing out on purpose is LoggedOut.
 */
class SessionEnded
{
    use Dispatchable, SerializesModels;

    /**
     * Keyring's own reasons are 'revoked', 'expired', 'idle', 'other_user',
     * 'reused', 'risk' and 'not_allowed'. A subclass of the session
     * middleware may sign out for one of its own.
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly string $reason,
    ) {}
}
