<?php

namespace Keyring\Risk\Signals;

use Keyring\Changes\EmailChanges;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;
use Keyring\Support\Duration;

/**
 * The email address changed recently. Recovery details that just changed
 * shouldn't be trusted on their own.
 */
class RecentlyChangedRecovery extends Signal
{
    public function __construct(
        protected EmailChanges $changes,
        protected int $score = 25,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $changed = $this->changes->lastChangedAt($assessment->user);
        $window = Duration::seconds(config('keyring.risk.recent_change'));

        return $changed !== null && $changed->getTimestamp() >= now()->getTimestamp() - $window
            ? new Finding('recent_recovery_change', $this->score, 'The email address changed recently.')
            : null;
    }
}
