<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Validation\ValidationException;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Contracts\Responses\LockoutResponse as LockoutResponseContract;
use Keyring\Pipeline\Context;
use Keyring\Support\Duration;
use Keyring\Support\Throttle;

class LockoutResponse implements LockoutResponseContract
{
    public function __construct(
        protected Context $context,
    ) {}

    public function toResponse($request)
    {
        // No lock that lifts by itself outlasts "longest_lock". Past that
        // it's the cap on failures in a row, or a lock that's held, and
        // counting it down helps nobody: say what ends it instead.
        throw $this->context->retryAfter !== null && $this->context->retryAfter <= Duration::seconds(config('keyring.limits.longest_lock'))
            ? Throttle::exception($this->context->errorKey(), $this->context->retryAfter)
            : ValidationException::withMessages([$this->context->errorKey() => $this->locked()])->status(429);
    }

    /**
     * A password reset clears a factor that can start a sign in. Any other
     * is set up again, once its user has signed in another way.
     */
    protected function locked(): string
    {
        $factor = $this->context->factor;

        return __($factor instanceof PrimaryFactor && $factor->startsLogin() ? 'keyring::keyring.locked' : 'keyring::keyring.factor_locked');
    }
}
