<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Cache\Repository;
use Keyring\Events\Lockout;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;

/**
 * Checks the factor's rate limits, counts attempts and locks out repeated failures.
 */
class EnsureNotThrottled
{
    public function __construct(
        protected RateLimiter $limiter,
        protected Repository $cache,
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $limits = $context->factor->limits($context->request, $context->attempt);

        foreach ($limits as $limit) {
            $lockedUntil = (int) $this->cache->get($this->key($limit).':locked', 0);

            if ($lockedUntil > now()->getTimestamp()) {
                return $this->lockout($context, $lockedUntil - now()->getTimestamp());
            }
        }

        // Count the attempt before verifying it, so overlapping requests
        // can't all slip under the limit while they're being checked.
        foreach ($limits as $limit) {
            if ($this->limiter->hit($this->key($limit), $limit->decaySeconds) > $limit->maxAttempts) {
                return $this->lockout($context, $this->limiter->availableIn($this->key($limit)));
            }
        }

        $context = $next($context);

        $succeeded = in_array($context->outcome, [Outcome::Challenge, Outcome::Complete], true);

        foreach ($limits as $limit) {
            match (true) {
                $context->outcome === Outcome::Failed => $this->failed($limit),
                $succeeded && $this->shared($limit) => $this->limiter->decrement($this->key($limit), $limit->decaySeconds),
                $succeeded => $this->limiter->clear($this->key($limit)),
                default => null,
            };
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
        $key = $this->key($limit);

        if ($this->limiter->attempts($key) < $limit->maxAttempts) {
            return;
        }

        $lockouts = $this->limiter->hit($key.':lockouts', 86400);
        $seconds = min(86400, $limit->decaySeconds * 2 ** ($lockouts - 1));

        $this->cache->put($key.':locked', now()->getTimestamp() + $seconds, $seconds);
        $this->limiter->clear($key);
    }

    /**
     * Limits shared by every account (per IP). A success only takes back its
     * own hit, so people signing in from one office IP don't use up its
     * limit, and an attacker can't reset it with their own login.
     */
    protected function shared(Limit $limit): bool
    {
        return str_contains((string) $limit->key, '|ip|');
    }

    protected function lockout(Context $context, int $retryAfter): Context
    {
        Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);

        return $context->lockout($retryAfter);
    }

    protected function key(Limit $limit): string
    {
        return 'keyring:'.sha1((string) $limit->key);
    }
}
