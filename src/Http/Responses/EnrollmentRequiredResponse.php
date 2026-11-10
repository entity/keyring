<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Keyring\Contracts\Responses\EnrollmentRequiredResponse as EnrollmentRequiredResponseContract;
use Keyring\Facades\Keyring;

class EnrollmentRequiredResponse implements EnrollmentRequiredResponseContract
{
    use ChoosesFormat;

    /**
     * To keyring.enrollment_url, or a 403 when there isn't one.
     */
    public function toResponse($request)
    {
        $url = config('keyring.enrollment_url');
        $message = Keyring::statusMessage('enroll-first');

        if ($this->wantsJson($request)) {
            return new JsonResponse(['status' => 'enroll-first', 'message' => $message, 'redirect' => $url], 403);
        }

        abort_if($url === null, 403, $message);

        return redirect($url)->with('status', 'enroll-first');
    }
}
