<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Keyring\Contracts\Responses\AuthenticatedResponse as AuthenticatedResponseContract;

class AuthenticatedResponse implements AuthenticatedResponseContract
{
    use ChoosesFormat;

    public function toResponse($request)
    {
        $redirect = redirect()->intended(config('keyring.home'));

        return $this->wantsJson($request)
            ? new JsonResponse(['status' => 'authenticated', 'redirect' => $redirect->getTargetUrl()])
            : $redirect;
    }
}
