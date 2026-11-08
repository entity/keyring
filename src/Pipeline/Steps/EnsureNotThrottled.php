<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Keyring\Events\Lockout;
use Keyring\Pipeline\ConsecutiveLimit;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Pipeline\SharedLimit;

/**
 * Checks the factor's rate limits, counts attempts and locks out repeated failures.
 */
class EnsureNotThrottled
{
    public function __construct(
        protected RateLimiter $limiter,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $limits = $context->factor->limits($context->request, $context->attempt);

        foreach ($limits as $limit) {
            $key = $limit instanceof ConsecutiveLimit ? static::key($limit) : $this->lock($limit);

            if ($this->limiter->tooManyAttempts($key, $limit instanceof ConsecutiveLimit ? $limit->maxAttempts : 1)) {
                return $this->lockout($context, $this->limiter->availableIn($key));
            }
        }

        // Count the attempt before verifying it, so overlapping requests
        // can't all slip under the limit while they're being checked.
        foreach (array_filter($limits, fn (Limit $limit) => ! $limit instanceof ConsecutiveLimit) as $limit) {
            if ($this->limiter->hit(static::key($limit), $limit->decaySeconds) > $limit->maxAttempts) {
                return $this->lockout($context, $this->limiter->availableIn(static::key($limit)));
            }
        }

        $context = $next($context);

        foreach ($limits as $limit) {
            if ($context->outcome === Outcome::Failed) {
                $this->failed($limit);
            } elseif (in_array($context->outcome, [Outcome::Challenge, Outcome::Complete], true)) {
                $this->succeeded($limit);
            }
        }

        return $context;
    }

    /**
     * Once a key reaches its limit, lock it. Each lock lasts twice as long as
     * the last one (OWASP), up to a day. The lockout count resets a day after
     * the first lockout.
     */
    protected function failed(Limit $limit): void
    {
        $key = static::key($limit);

        // Counted here, not up front, so it's failures in a row: no window,
        // no lock of its own, just refused at the cap until a success.
        if ($limit instanceof ConsecutiveLimit) {
            $this->limiter->hit($key, $limit->decaySeconds);

            return;
        }

        if ($this->limiter->attempts($key) < $limit->maxAttempts) {
            return;
        }

        $lockouts = $this->limiter->hit($key.':lockouts', 86400);

        $this->limiter->hit($this->lock($limit), min(86400, $limit->decaySeconds * 2 ** ($lockouts - 1)));
        $this->limiter->clear($key);
    }

    /**
     * A success clears an account's count. On a shared limit it only takes
     * back its own attempt: people signing in from one office address don't
     * use it up, and an attacker can't reset it with their own login.
     */
    protected function succeeded(Limit $limit): void
    {
        $limit instanceof SharedLimit
            ? $this->limiter->decrement(static::key($limit), $limit->decaySeconds)
            : $this->limiter->clear(static::key($limit));
    }

    protected function lockout(Context $context, int $retryAfter): Context
    {
        Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);

        return $context->lockout($retryAfter);
    }

    /**
     * The rate limiter key for a limit.
     */
    public static function key(Limit $limit): string
    {
        return 'keyring:'.sha1((string) $limit->key);
    }

    protected function lock(Limit $limit): string
    {
        return static::key($limit).':locked';
    }
}
