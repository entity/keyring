<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\Response;
use Keyring\Contracts\Responses\LogoutResponse as LogoutResponseContract;

class LogoutResponse implements LogoutResponseContract
{
    use ChoosesFormat;

    public function toResponse($request)
    {
        // As on any sign out: nothing the session cached stays in the browser.
        return $this->clearSiteData($this->wantsJson($request) ? new Response(status: 204) : redirect('/'));
    }
}
