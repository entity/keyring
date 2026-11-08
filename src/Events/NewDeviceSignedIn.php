<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Models\Device;

/**
 * Someone signed in from a device this account hasn't used before. Keyring
 * emails the user about it when the "new_device" security email is on.
 */
class NewDeviceSignedIn
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Device $device,
    ) {}

    /**
     * A signed "this wasn't me" link that signs the device out.
     */
    public function revokeUrl(int $days = 7): string
    {
        return $this->device->revokeUrl($days);
    }
}
