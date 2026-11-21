<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Illuminate\Support\Collection;
use Keyring\Sessions\RegisteredSession;
use RuntimeException;
use Throwable;

/**
 * A registry driver revoked some of the records a call asked for, then
 * failed. It carries the records it did revoke, so they are still
 * announced (AnnouncingSessionRegistry), and the failure as the previous
 * exception, which is what's thrown on from there.
 */
class PartialRevocation extends RuntimeException
{
    /**
     * @param  Collection<int, RegisteredSession>  $revoked
     */
    public function __construct(
        public readonly Collection $revoked,
        Throwable $previous,
    ) {
        // Not the failure's own message, which can name a record (a cache
        // key holds its ID): that's the previous exception's to say.
        parent::__construct('Some sessions were revoked before the session registry failed.', 0, $previous);
    }
}
