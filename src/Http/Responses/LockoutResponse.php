<?php

namespace Keyring\Http\Responses;

use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Responses\LockoutResponse as LockoutResponseContract;
use Keyring\Facades\Keyring;
use Keyring\Pipeline\Context;

class LockoutResponse implements LockoutResponseContract
{
    public function __construct(
        protected Context $context,
    ) {}

    public function toResponse($request)
    {
        $key = $this->context->identifying
            ? Keyring::username()
            : $this->context->factor->errorKey();

        throw ValidationException::withMessages([
            $key => __('auth.throttle', [
                'seconds' => $this->context->retryAfter,
                'minutes' => ceil($this->context->retryAfter / 60),
            ]),
        ])->status(429);
    }
}
