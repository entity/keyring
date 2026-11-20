<?php

declare(strict_types=1);

namespace Keyring\Risk\Signals;

use Keyring\Activity\SecurityLog;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;
use Keyring\Support\Duration;

/**
 * A first factor that's right, from an IP address where several other
 * accounts recently failed a factor: what working through a list of leaked
 * passwords looks like when one of them fits.
 *
 * It counts accounts, not attempts, so many failures on one account count
 * once (SuccessAfterFailures and RepeatedFactorFailures are for those), and
 * the user's own failures don't count. A failure is any factor_failed entry:
 * a wrong password or passkey at sign in, but also a wrong second factor or
 * a wrong password at a confirm prompt. Failures for a name nobody has don't
 * say which name was typed, so they can't be told apart, and together they
 * count as one account: someone retyping a mistyped address isn't a list.
 *
 * Only failures from the same address count, so a stranger can only raise
 * the risk of sign ins made from where they are. A shared address (an
 * office, a mobile network) can fire it for its other users, and so can a
 * proxy Laravel doesn't trust, or a frontend that posts the login from its
 * own server, which put everyone on one address. That's why it's off unless
 * turned on. Reads the security log, and compares the address Keyring
 * records (Keyring::recordIpsUsing()).
 */
class CredentialStuffing extends Signal
{
    /** What its finding is called, in Risk::has(). */
    public const string FINDING = 'credential_stuffing';

    public function __construct(
        protected SecurityLog $log,
        protected int $threshold = 5,
        protected int $score = 40,
        protected string $within = '1h',
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $accounts = $this->log->accountsFrom($assessment->request, 'factor_failed', Duration::seconds($this->within), except: $assessment->user);

        return $accounts >= $this->threshold
            ? new Finding(self::FINDING, $this->score, "Failed attempts on {$accounts} other accounts from this IP address in the last {$this->within}.")
            : null;
    }
}
