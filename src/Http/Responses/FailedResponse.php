<?php

declare(strict_types=1);

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
            $this->context->errorKey() => match (true) {
                $this->context->identifying => __('auth.failed'),
                $this->context->attempt?->exhausted === true => __('keyring::keyring.too_many_codes'),
                default => __('keyring::keyring.invalid'),
            },
        ]);
    }
}
