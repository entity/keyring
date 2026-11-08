<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Models\PendingChange;

/**
 * The email address changed. The old address can still revert it for a while.
 */
class EmailChanged
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly PendingChange $change,
    ) {}
}
