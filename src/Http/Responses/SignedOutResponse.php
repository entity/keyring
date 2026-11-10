<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Keyring\Contracts\Responses\SignedOutResponse as SignedOutResponseContract;
use Keyring\Facades\Keyring;

class SignedOutResponse implements SignedOutResponseContract
{
    use ChoosesFormat;

    /**
     * @param  'revoked'|'expired'|'idle'|'other_user'|'risk'|'not_allowed'  $reason
     */
    public function __construct(
        public readonly string $reason,
    ) {}

    /**
     * Like Laravel's own auth middleware: 401 for JSON, otherwise back to
     * login, remembering where they were going.
     */
    public function toResponse($request)
    {
        redirect()->setIntendedUrl($this->intendedUrl($request));

        $response = $this->wantsJson($request)
            ? new JsonResponse(['status' => 'signed-out', 'message' => Keyring::statusMessage('signed-out')], 401)
            : to_route('login')->with('status', 'signed-out');

        // As on sign out: nothing the session cached stays in the browser.
        $response->headers->set('Clear-Site-Data', '"cache", "storage"');

        return $response;
    }
}
