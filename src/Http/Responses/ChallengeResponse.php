<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Keyring\Contracts\Responses\ChallengeResponse as ChallengeResponseContract;
use Keyring\Enums\Purpose;
use Keyring\Pipeline\Context;

class ChallengeResponse implements ChallengeResponseContract
{
    use ChoosesFormat;

    public function __construct(
        protected Context $context,
    ) {}

    public function toResponse($request)
    {
        $purpose = $this->context->purpose;
        $url = route('keyring.'.$purpose->value.'.challenge');

        // The page by name too, for a frontend whose pages aren't at
        // Keyring's URLs: "challenge" at sign in, "confirm" for step-up.
        return $this->wantsJson($request)
            ? new JsonResponse(['status' => 'challenge', 'page' => $purpose === Purpose::Login ? 'challenge' : 'confirm', 'redirect' => $url], 202)
            : redirect($url);
    }
}
