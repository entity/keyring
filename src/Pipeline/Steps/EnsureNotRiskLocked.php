<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Enums\Purpose;
use Keyring\Pipeline\Context;
use Keyring\Risk\RiskLocks;

/**
 * Refuses a login for a user under a risk lock, with the same generic error
 * as a wrong password. Separate from AssessRisk, so replacing that keeps it.
 */
class EnsureNotRiskLocked
{
    public function __construct(
        protected RiskLocks $locks,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $context->riskLockChecked = true;

        if ($context->attempt->purpose === Purpose::Login && $this->locks->locked($context->attempt->user())) {
            return $context->fail();
        }

        return $next($context);
    }
}
