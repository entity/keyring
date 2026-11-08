<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Enums\Purpose;
use Keyring\Pipeline\Context;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\RiskEngine;
use Keyring\Risk\RiskLocks;

/**
 * Runs the risk signals once per login, then acts: allow, ask for another
 * factor, or refuse (with the same generic error as a wrong password).
 */
class AssessRisk
{
    public function __construct(
        protected RiskEngine $engine,
        protected RiskLocks $locks,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $attempt = $context->attempt;

        if ($attempt->purpose !== Purpose::Login) {
            return $next($context);
        }

        $user = $attempt->user();

        if ($this->locks->locked($user)) {
            return $context->fail();
        }

        if ($attempt->risk === null) {
            $risk = $this->engine->assess(new Assessment(Checkpoint::Login, $context->request, $user, $attempt));
            $action = $this->engine->enforce($user, $risk, Checkpoint::Login);

            $attempt->risk = $risk;
            $attempt->stepUp = $action->stepUp;

            if ($action->deny) {
                return $context->fail();
            }
        }

        return $next($context);
    }
}
