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
        // A wait longer than any lock that lifts by itself is the in-a-row
        // cap or a lock that's held. Counting it down in seconds helps
        // nobody, and for a factor that can start a sign in a password
        // reset ends it.
        throw $this->context->factor instanceof PrimaryFactor && $this->context->retryAfter > Duration::seconds(config('keyring.limits.longest_lock'))
            ? ValidationException::withMessages([$this->context->errorKey() => __('keyring::keyring.locked')])->status(429)
            : Throttle::exception($this->context->errorKey(), $this->context->retryAfter);
    }
}
