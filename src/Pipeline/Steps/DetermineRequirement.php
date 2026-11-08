<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Enums\Purpose;
use Keyring\KeyringManager;
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
            $attempt->requirement = $this->keyring->requirementFor($attempt->user(), $attempt);
        }

        return $next($context);
    }
}
