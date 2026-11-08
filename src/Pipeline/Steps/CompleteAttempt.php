<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Enums\Purpose;
use Keyring\Login\AttemptStore;
use Keyring\Login\SignIn;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;

/**
 * Signs the user in (or confirms them) once the requirement is met, or saves
 * the attempt and asks for another factor.
 */
class CompleteAttempt
{
    public function __construct(
        protected AttemptStore $attempts,
        protected SignIn $signIn,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $attempt = $context->attempt;

        if (! $attempt->complete) {
            $this->attempts->save($attempt);
            $context->outcome = Outcome::Challenge;

            return $next($context);
        }

        $this->attempts->forget($attempt->purpose);

        $attempt->purpose === Purpose::Login
            ? $this->signIn->complete($context->request, $attempt)
            : $this->signIn->confirm($context->request, $attempt);

        $context->outcome = Outcome::Complete;

        return $next($context);
    }
}
