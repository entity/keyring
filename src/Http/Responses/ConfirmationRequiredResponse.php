<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Keyring\Contracts\Responses\ConfirmationRequiredResponse as ConfirmationRequiredResponseContract;

class ConfirmationRequiredResponse implements ConfirmationRequiredResponseContract
{
    use ChoosesFormat;

    /**
     * To the confirm page, coming back here afterwards. JSON callers get a
     * 423 with where to send the browser.
     */
    public function toResponse($request)
    {
        redirect()->setIntendedUrl($this->intendedUrl($request));

        $url = route('keyring.confirm.challenge');

        return $this->wantsJson($request)
            ? new JsonResponse(['message' => __('keyring::keyring.confirm'), 'redirect' => $url], 423)
            : redirect($url);
    }
}
