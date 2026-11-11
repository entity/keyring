<?php

declare(strict_types=1);

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Cache\RateLimiting\Limit;
use Keyring\Events\AccountLocked;
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
        [$quiet, $limits] = $this->throttle->split($context->factor->limits($context->request, $context->attempt));

        if (($retryAfter = $this->throttle->hit($limits)) !== null) {
            Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);

            return $context->lockout($retryAfter);
        }

        $context->throttleChecked = true;

        // A quiet limit's refusal isn't answered here. The attempt carries
        // on, to fail like a wrong proof and count like one against the
        // limits that let it through.
        if (($retryAfter = $this->throttle->hit($quiet)) !== null) {
            $context->refuse($retryAfter);
        } else {
            $limits = [...$limits, ...$quiet];
        }

        $context = $next($context);

        match ($context->outcome) {
            Outcome::Failed => $this->failed($context, $limits),
            Outcome::Challenge, Outcome::Complete => $this->throttle->succeeded($limits),
            default => null,
        };

        return $context;
    }

    /**
     * Count the failure, and say so when it locked the account until its
     * limits are cleared. Nobody is told for a name that found no account.
     *
     * @param  list<Limit>  $limits
     */
    protected function failed(Context $context, array $limits): void
    {
        if ($this->throttle->failed($limits) && $context->attempt !== null) {
            AccountLocked::dispatch($context->attempt->user(), $context->factor->key());
        }
    }
}
