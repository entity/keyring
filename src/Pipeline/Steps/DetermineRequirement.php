<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Enums\Purpose;
use Keyring\KeyringManager;
use Keyring\Login\Requirement;
use Keyring\Pipeline\Context;

/**
 * Asks the policy what this login needs. Re-evaluated on every verification,
 * so later steps (like risk) can raise it mid-login.
 */
class DetermineRequirement
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $attempt = $context->attempt;

        if ($context->purpose === Purpose::Login || $attempt->requirement === null) {
            $requirement = $this->keyring->requirementFor($attempt->user(), $attempt);

            // Risk asked for more: add a second factor when the user has one.
            if ($attempt->stepUp && $attempt->keyring()->canMeet(Requirement::aal2())) {
                $requirement = $requirement->atLeast(Requirement::aal2());
            }

            $attempt->requirement = $requirement;
        }

        return $next($context);
    }
}
