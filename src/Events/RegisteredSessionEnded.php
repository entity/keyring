<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Enums\SessionEndReason;

/**
 * A registered session ended: one for each record the registry revoked,
 * whoever revoked it and wherever. Its data is plain, so a queued listener
 * gets it as it was.
 *
 * It names the session by its handle (Sessions::handle), never by its
 * registry ID: that is what the browser's "remember me" cookie carries.
 * $handles has the handle under each of the app's keys, the current one
 * first, so a handle kept from before APP_KEY was rotated still matches.
 *
 * $userType is the connection and table the user's ID is unique in
 * (RegisteredSession::typeOf), such as "mysql:users", not a class name.
 */
class RegisteredSessionEnded
{
    use Dispatchable;

    /**
     * @param  non-empty-list<string>  $handles
     */
    public function __construct(
        public readonly string $handle,
        public readonly array $handles,
        public readonly string $userId,
        public readonly string $userType,
        public readonly string $guard,
        public readonly ?string $deviceId,
        public readonly int $endedAt,
        public readonly SessionEndReason $reason,
    ) {}
}
