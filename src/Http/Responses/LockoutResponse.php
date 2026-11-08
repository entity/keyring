<?php

namespace Keyring\Http\Responses;

use Keyring\Contracts\Responses\LockoutResponse as LockoutResponseContract;
use Keyring\Pipeline\Context;
use Keyring\Support\Throttle;

class LockoutResponse implements LockoutResponseContract
{
    public function __construct(
        protected Context $context,
    ) {}

    public function toResponse($request)
    {
        throw Throttle::exception($this->context->errorKey(), $this->context->retryAfter);
    }
}
