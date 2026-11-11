<?php

declare(strict_types=1);

namespace Keyring\Risk\Signals;

use Keyring\Activity\SecurityLog;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;
use Keyring\Support\Duration;

class RepeatedFactorFailures extends Signal
{
    public function __construct(
        protected SecurityLog $log,
        protected int $threshold = 5,
        protected int $score = 25,
        protected string $within = '15m',
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        // Only failures after a correct first factor count. Anyone can type a
        // wrong password for a known email, so plain login failures would let
        // an anonymous party raise the owner's risk and get them locked out.
        $failures = $this->log->count($assessment->user, 'second_factor_failed', Duration::seconds($this->within));

        return $failures >= $this->threshold
            ? new Finding('repeated_failures', $failures >= $this->threshold * 2 ? $this->score * 2 : $this->score, "{$failures} failed second factors in the last {$this->within}.")
            : null;
    }
}
