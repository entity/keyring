<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * The password was reset from a reset link. Every session was signed out.
 */
class PasswordReset
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
