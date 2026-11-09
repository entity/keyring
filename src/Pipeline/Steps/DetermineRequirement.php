<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Validation\ValidationException;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\UnregisteredFactor;
use Keyring\KeyringManager;
use Keyring\Login\Requirement;
use Keyring\Pipeline\Context;

/**
 * Asks the policy what this login needs. Re-evaluated on every verification,
 * so later steps (like risk) can raise it mid-login.
 *
 * A user with authenticators for a factor that isn't registered is refused:
 * Keyring can't check those, and skipping them would let the password alone
 * through.
 */
class DetermineRequirement
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $attempt = $context->attempt;

        if (($unregistered = $attempt->keyring()->unregistered()) !== []) {
            report(UnregisteredFactor::for($attempt->user(), $unregistered));

            throw ValidationException::withMessages([$context->errorKey() => __('keyring::keyring.unavailable')]);
        }

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
