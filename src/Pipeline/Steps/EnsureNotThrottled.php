<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Keyring\Events\Lockout;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Support\Throttle;

/**
 * Checks the factor's rate limits, counts the attempt and locks out
 * repeated failures.
 */
class EnsureNotThrottled
{
    public function __construct(
        protected Throttle $throttle,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $limits = $context->factor->limits($context->request, $context->attempt);

        if (($retryAfter = $this->throttle->hit($limits)) !== null) {
            Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);

            return $context->lockout($retryAfter);
        }

        $context->throttleChecked = true;

        $context = $next($context);

        match ($context->outcome) {
            Outcome::Failed => $this->throttle->failed($limits),
            Outcome::Challenge, Outcome::Complete => $this->throttle->succeeded($limits),
            default => null,
        };

        return $context;
    }
}
