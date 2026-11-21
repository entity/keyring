<?php

declare(strict_types=1);

namespace Keyring\Sessions;

/**
 * What one run of the sweep did: how many timed-out sessions it ended, how
 * many it announced again, and whether it left some for the next run.
 */
final readonly class SweepResult
{
    public function __construct(
        public int $ended,
        public int $announcedAgain,
        public bool $more,
    ) {}
}
