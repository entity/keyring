<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Failed attempts locked the account out of a factor that can start a sign
 * in, until a password reset or Keyring::unlock() clears it. Only happens
 * with "limits.lock_after" set.
 */
class AccountLocked
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly string $factor,
    ) {}
}
