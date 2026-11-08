<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Keyring\Contracts\Responses\ChallengeResponse as ChallengeResponseContract;
use Keyring\Pipeline\Context;

class ChallengeResponse implements ChallengeResponseContract
{
    use ChoosesFormat;

    public function __construct(
        protected Context $context,
    ) {}

    public function toResponse($request)
    {
        $url = route('keyring.'.$this->context->purpose->value.'.challenge');

        return $this->wantsJson($request)
            ? new JsonResponse(['status' => 'challenge', 'redirect' => $url], 202)
            : redirect($url);
    }
}
