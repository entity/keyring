<?php

namespace Keyring\Risk\Signals;

use Keyring\Changes\EmailChanges;
use Keyring\Contracts\Signal;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Support\Duration;

/**
 * The email address changed recently. Recovery details that just changed
 * shouldn't be trusted on their own.
 */
class RecentlyChangedRecovery implements Signal
{
    public function __construct(
        protected EmailChanges $changes,
        protected int $score = 25,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $changed = $this->changes->lastChangedAt($assessment->user);
        $window = Duration::seconds(config('keyring.risk.recent_change', '7d'));

        return $changed !== null && $changed->getTimestamp() >= now()->getTimestamp() - $window
            ? new Finding('recent_recovery_change', $this->score, 'The email address changed recently.')
            : null;
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}
