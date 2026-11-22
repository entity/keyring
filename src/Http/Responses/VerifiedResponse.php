<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Uri;
use Keyring\Contracts\Responses\VerifiedResponse as VerifiedResponseContract;
use Keyring\Facades\Keyring;

class VerifiedResponse implements VerifiedResponseContract
{
    use ChoosesFormat;

    public function __construct(
        public readonly bool $justNow = false,
    ) {}

    /**
     * On to where they were going, with ?verified=1 when the link they
     * followed is what verified them. JSON callers get the same place as
     * the redirect, and whether it was just now.
     */
    public function toResponse($request)
    {
        $home = config('keyring.home');
        $redirect = redirect()->intended($this->justNow ? (string) Uri::of($home)->withQuery(['verified' => 1]) : $home);

        return $this->wantsJson($request)
            ? new JsonResponse([
                'status' => 'email-verified',
                'message' => Keyring::statusMessage('email-verified'),
                'justNow' => $this->justNow,
                'redirect' => $redirect->getTargetUrl(),
            ])
            : $redirect;
    }
}
