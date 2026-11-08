<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * The user changed their password. Worth telling them by email.
 */
class PasswordChanged
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
