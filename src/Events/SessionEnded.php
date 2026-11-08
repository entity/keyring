<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Keyring signed a session out on its own: it was revoked, timed out, or a
 * risk response ended it. Signing out on purpose is LoggedOut.
 */
class SessionEnded
{
    use Dispatchable, SerializesModels;

    /**
     * @param  'revoked'|'expired'|'idle'|'other_user'|'risk'  $reason
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly string $reason,
    ) {}
}
