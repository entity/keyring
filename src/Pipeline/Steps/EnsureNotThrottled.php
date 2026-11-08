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
 * Checks the factor's rate limits, counts failures and clears them on success.
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

            if ($this->limiter->tooManyAttempts($this->key($limit), $limit->maxAttempts)) {
                return $this->lockout($context, $this->limiter->availableIn($this->key($limit)));
            }
        }

        $context = $next($context);

        foreach ($limits as $limit) {
            $key = $this->key($limit);

            if ($context->outcome === Outcome::Failed) {
                $this->failed($limit);
            } elseif (in_array($context->outcome, [Outcome::Challenge, Outcome::Complete], true)) {
                $this->limiter->clear($key);
            }
        }

        return $context;
    }

    /**
     * Count a failure. Each time a key locks out, the lock lasts twice as long
     * as the last one (OWASP), up to a day. The count resets a day after the
     * last lockout.
     */
    protected function failed(Limit $limit): void
    {
        $key = $this->key($limit);

        if ($this->limiter->hit($key, $limit->decaySeconds) < $limit->maxAttempts) {
            return;
        }

        $lockouts = $this->limiter->hit($key.':lockouts', 86400);
        $seconds = min(86400, $limit->decaySeconds * 2 ** ($lockouts - 1));

        $this->cache->put($key.':locked', now()->getTimestamp() + $seconds, $seconds);
        $this->limiter->clear($key);
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
