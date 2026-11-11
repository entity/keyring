<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Sessions\RegisteredSession;

/**
 * A "remember me" cookie carried a session on after it had gone unused: the
 * browser is signed in again with nothing proved. The record is the one the
 * session moved to.
 */
class SessionResumed
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly RegisteredSession $session,
    ) {}
}
