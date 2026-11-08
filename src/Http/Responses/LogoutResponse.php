<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\Response;
use Keyring\Contracts\Responses\LogoutResponse as LogoutResponseContract;

class LogoutResponse implements LogoutResponseContract
{
    use ChoosesFormat;

    public function toResponse($request)
    {
        return $this->wantsJson($request) ? new Response(status: 204) : redirect('/');
    }
}
