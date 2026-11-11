<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Login\Attempt;
use Keyring\Models\Device;

/**
 * A login completed and the user was signed in.
 */
class Authenticated
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Attempt $attempt,
        public readonly ?Device $device = null,
    ) {}
}
