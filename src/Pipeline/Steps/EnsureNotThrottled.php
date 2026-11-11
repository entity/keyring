<?php

declare(strict_types=1);

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Arr;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Events\AccountLocked;
use Keyring\Events\Lockout;
use Keyring\Pipeline\AccountLimit;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Pipeline\SharedLimit;
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

        [$quiet, $announced] = $this->throttle->split($limits);
        [$shared, $named] = Arr::partition($announced, fn (Limit $limit) => $limit instanceof SharedLimit);
        [$shared, $named] = [array_values($shared), array_values($named)];

        // With no quiet limit there's nothing behind the ones that say so:
        // they're asked together, and an attempt one of them refuses is
        // counted against none, the address's included.
        if ($quiet === []) {
            if (($refusing = $this->throttle->hit($announced)) !== null) {
                return $this->lockedOut($context, $refusing);
            }

            return $this->counted($context, $next, $announced);
        }

        // The address first, so an attempt it refuses is never counted
        // against the account.
        if (($refusing = $this->throttle->hit($shared)) !== null) {
            return $this->lockedOut($context, $refusing);
        }

        // A typed name that's refused says so, but not yet: whether a name
        // is refused goes only by what was tried under it, so that it
        // doesn't show which names have an account. The account behind it,
        // if there is one, has limits of its own, and those decide whether
        // the proof is looked at. So an owner who has just reset their
        // password gets in with it under a name someone else got refused,
        // and everyone without the password is answered as the name is.
        $held = $this->throttle->hit($named);
        $limits = [...$shared, ...($held === null ? $named : [])];

        $context->throttleChecked = true;

        // A quiet limit's refusal isn't answered here. The attempt carries
        // on, to fail like a wrong proof and count like one against the
        // limits that let it through.
        if (($refusing = $this->throttle->hit($quiet)) !== null) {
            $context->refuse($this->throttle->retryAfter($refusing));
        } elseif ($held !== null && array_all($quiet, fn (Limit $limit) => $limit instanceof AccountLimit && $limit->unowned)) {
            // Nobody is behind the name, so there's no proof to look at:
            // refused like an account whose own limits are used up, at the
            // same cost.
            $context->refuse($this->throttle->retryAfter($held));
        } else {
            $limits = [...$limits, ...$quiet];
        }

        // A name that was refused stays so when the attempt goes through:
        // what it answers isn't changed by the account behind it signing in.
        $context = $this->counted($context, $next, $limits);

        // A quiet refusal has been announced to the app already, where the
        // proof would have been checked.
        return $held !== null && $context->outcome === Outcome::Failed
            ? $this->lockedOut($context, $held, announce: ! $context->refused)
            : $context;
    }

    /**
     * Carry on down the pipeline with the attempt counted against these
     * limits, and settle them by how it went.
     *
     * @param  list<Limit>  $limits
     */
    protected function counted(Context $context, Closure $next, array $limits): Context
    {
        $context->throttleChecked = true;

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

    protected function lockedOut(Context $context, Limit $refusing, bool $announce = true): Context
    {
        $retryAfter = $this->throttle->retryAfter($refusing);

        if ($announce) {
            Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);
        }

        return $context->lockout($retryAfter);
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
