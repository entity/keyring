<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Models\Device;

/**
 * A device was signed out. "Reported" means the user said it wasn't them,
 * which is a good moment to ask them to change their password.
 */
class DeviceRevoked
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Device $device,
        public readonly bool $reported = false,
    ) {}
}
