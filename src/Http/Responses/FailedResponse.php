<?php

namespace Keyring\Http\Responses;

use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Responses\FailedResponse as FailedResponseContract;
use Keyring\Pipeline\Context;

class FailedResponse implements FailedResponseContract
{
    public function __construct(
        protected Context $context,
    ) {}

    /**
     * The same message whether the account doesn't exist or the proof was
     * wrong, so the response doesn't reveal which accounts exist.
     */
    public function toResponse($request)
    {
        throw ValidationException::withMessages([
            $this->context->errorKey() => $this->context->identifying
                ? __('auth.failed')
                : __('keyring::keyring.invalid'),
        ]);
    }
}
