<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * A user was held until they choose a new password: a risk response or the
 * app found reason to think theirs is known to someone else.
 */
class PasswordChangeRequired
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly ?string $reason = null,
    ) {}
}
