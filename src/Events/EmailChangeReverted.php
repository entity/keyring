<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Models\PendingChange;

/**
 * Someone used the "this wasn't me" link. Every session was signed out.
 */
class EmailChangeReverted
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly PendingChange $change,
    ) {}
}
