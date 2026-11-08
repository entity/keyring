<?php

namespace Keyring\Risk\Signals;

use Keyring\Activity\SecurityLog;
use Keyring\Contracts\Signal;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;

class RepeatedFactorFailures implements Signal
{
    public function __construct(
        protected SecurityLog $log,
        protected int $threshold = 5,
        protected int $score = 25,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $failures = $this->log->count($assessment->user, 'factor_failed', 15 * 60);

        return $failures >= $this->threshold
            ? new Finding('repeated_failures', $failures >= $this->threshold * 2 ? $this->score * 2 : $this->score, "{$failures} failed attempts in the last 15 minutes.")
            : null;
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}
