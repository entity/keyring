<?php

declare(strict_types=1);

namespace Keyring\Risk\Signals;

use Keyring\Activity\SecurityLog;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;
use Keyring\Support\Duration;

/**
 * A sign in that gets its first factor right after several failed attempts
 * on the account since it last signed in: what a password that was finally
 * guessed looks like, and also one its owner half remembered.
 *
 * Unlike RepeatedFactorFailures, this counts failures anyone can cause, since
 * typing a wrong password takes no more than the username. It can't tell who
 * failed, so it's worth telling the owner about or asking for another factor,
 * and its score is kept to what does that. Reads the security log.
 */
class SuccessAfterFailures extends Signal
{
    /** What its finding is called, in Risk::has(). */
    public const string FINDING = 'success_after_failures';

    public function __construct(
        protected SecurityLog $log,
        protected int $threshold = 5,
        protected int $score = 30,
        protected string $within = '1h',
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $failures = $this->log->count($assessment->user, 'factor_failed', Duration::seconds($this->within), since: 'signed_in');

        return $failures >= $this->threshold
            ? new Finding(self::FINDING, $this->score, "Signed in after {$failures} failed attempts in the last {$this->within}.")
            : null;
    }
}
