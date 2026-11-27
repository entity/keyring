<?php

declare(strict_types=1);

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
        throw Throttle::lockedOut($this->context->factor, $this->context->errorKey(), $this->context->retryAfter);
    }
}
