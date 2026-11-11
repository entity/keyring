<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Sessions\RegisteredSession;

/**
 * A "remember me" cookie that had already been used, or a session still
 * open from before it was, turned up again. Each cookie works once, so two
 * browsers held the same ones, and the session was ended for both. The
 * record is the one that was ended: its device, address and browser are
 * those of whoever used the cookie first.
 */
class RememberMeReused
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly RegisteredSession $session,
    ) {}
}
