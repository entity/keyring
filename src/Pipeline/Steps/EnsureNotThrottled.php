<?php

namespace Keyring\Pipeline\Steps;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\RateLimiting\Limit;
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
    ) {}

    public function handle(Context $context, Closure $next): Context
    {
        $limits = $context->factor->limits($context->request, $context->attempt);

        foreach ($limits as $limit) {
            if ($this->limiter->tooManyAttempts($this->key($limit), $limit->maxAttempts)) {
                $retryAfter = $this->limiter->availableIn($this->key($limit));

                Lockout::dispatch($context->request, $context->factor->key(), $retryAfter);

                return $context->lockout($retryAfter);
            }
        }

        $context = $next($context);

        foreach ($limits as $limit) {
            match ($context->outcome) {
                Outcome::Failed => $this->limiter->hit($this->key($limit), $limit->decaySeconds),
                Outcome::Challenge, Outcome::Complete => $this->limiter->clear($this->key($limit)),
                default => null,
            };
        }

        return $context;
    }

    protected function key(Limit $limit): string
    {
        return 'keyring:'.sha1((string) $limit->key);
    }
}
