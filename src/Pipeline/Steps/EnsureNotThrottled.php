<?php

declare(strict_types=1);

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Cache\RateLimiting\Limit;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Events\AccountLocked;
use Keyring\Events\Lockout;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Support\Throttle;
use Throwable;

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
        $limits = $this->throttle->aim($context->factor->limits($context->request, $context->attempt), $context);

        [$quiet, $limits] = $this->throttle->split($limits);

        if (($refusing = $this->throttle->hit($limits)) !== null) {
            $retryAfter = $this->throttle->retryAfter($refusing);

            Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);

            return $context->lockout($retryAfter);
        }

        $context->throttleChecked = true;

        // A quiet limit's refusal isn't answered here. The attempt carries
        // on, to fail like a wrong proof and count like one against the
        // limits that let it through.
        if (($refusing = $this->throttle->hit($quiet)) !== null) {
            $context->refuse($this->throttle->retryAfter($refusing));
        } else {
            $limits = [...$limits, ...$quiet];
        }

        try {
            $context = $next($context);
        } catch (Throwable $e) {
            $this->throttle->release($limits);

            throw $e;
        }

        match ($context->outcome) {
            Outcome::Failed => $this->failed($context, $limits),
            Outcome::Challenge, Outcome::Complete => $this->throttle->succeeded($limits),
            default => $this->throttle->release($limits),
        };

        return $context;
    }

    /**
     * Count the failure, and say so when it got a factor that can start a
     * sign in refused for the account until its limits are cleared. Nobody
     * is told for a name that found no account, and a second factor has no
     * event: its user is told on the challenge page, and signs in another
     * way.
     *
     * @param  list<Limit>  $limits
     */
    protected function failed(Context $context, array $limits): void
    {
        $factor = $context->factor;

        if ($this->throttle->failed($limits) && $context->attempt !== null && $factor instanceof PrimaryFactor && $factor->startsLogin()) {
            AccountLocked::dispatch($context->attempt->user(), $factor->key());
        }
    }
}
