<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Uri;
use Keyring\Contracts\Responses\PasswordChangeRequiredResponse as PasswordChangeRequiredResponseContract;
use Keyring\Facades\Keyring;

class PasswordChangeRequiredResponse implements PasswordChangeRequiredResponseContract
{
    use ChoosesFormat;

    /**
     * To keyring.password_change_url, or a 403 when there isn't one or the
     * request is already for it, which would only go round in a loop.
     */
    public function toResponse($request)
    {
        $url = config('keyring.password_change_url');
        $message = Keyring::statusMessage('change-password');

        if ($this->wantsJson($request)) {
            return new JsonResponse(['status' => 'change-password', 'message' => $message, 'redirect' => $url], 403);
        }

        abort_if($url === null || $request->is(Uri::of($url)->path()), 403, $message ?? '');

        return redirect($url)->with('status', 'change-password');
    }
}
