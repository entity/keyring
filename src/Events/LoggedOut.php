<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * The user signed out.
 */
class LoggedOut
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
    ) {}
}
