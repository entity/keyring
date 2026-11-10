<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Uri;
use Keyring\Contracts\Responses\EnrollmentRequiredResponse as EnrollmentRequiredResponseContract;
use Keyring\Facades\Keyring;

class EnrollmentRequiredResponse implements EnrollmentRequiredResponseContract
{
    use ChoosesFormat;

    /**
     * To keyring.enrollment_url, or a 403 when there isn't one or the
     * request is already for it, which would only go round in a loop.
     */
    public function toResponse($request)
    {
        $url = config('keyring.enrollment_url');
        $message = Keyring::statusMessage('enroll-first');

        if ($this->wantsJson($request)) {
            return new JsonResponse(['status' => 'enroll-first', 'message' => $message, 'redirect' => $url], 403);
        }

        // Already there: the page itself asks for what it's there to set up.
        abort_if($url === null || $request->is(Uri::of($url)->path()), 403, $message ?? '');

        return redirect($url)->with('status', 'enroll-first');
    }
}
