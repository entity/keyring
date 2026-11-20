<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Keyring\Enums\SessionEndReason;

/**
 * A record that ended, and why: what a sweep hands back to be announced.
 */
final readonly class EndedSession
{
    public function __construct(
        #[\SensitiveParameter] public RegisteredSession $session,
        public SessionEndReason $reason,
    ) {}
}
