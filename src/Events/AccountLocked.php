<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Failed attempts got a factor that can start a sign in refused for the
 * account, until a password reset or Keyring::unlock() clears it: it used
 * up its failures in a row, or "limits.lock_after" held it. Browsers the
 * account has signed in from may still be let in.
 */
class AccountLocked
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly string $factor,
    ) {}
}
