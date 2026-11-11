<?php

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * A signed-in user asked for something that isn't theirs: someone else's
 * authenticator or device (or one that doesn't exist, which is answered
 * with the same 404 and not told apart here), or an email verification
 * link made for another account.
 */
class AccessRefused
{
    use Dispatchable, SerializesModels;

    /**
     * @param  string  $resource  what was asked for: "authenticator", "device" or "email_verification"
     * @param  string  $id  the ID the request sent, whatever it was
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly string $resource,
        public readonly string $id,
    ) {}
}
