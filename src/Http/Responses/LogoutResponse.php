<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\Response;
use Keyring\Contracts\Responses\LogoutResponse as LogoutResponseContract;

class LogoutResponse implements LogoutResponseContract
{
    use ChoosesFormat;

    public function toResponse($request)
    {
        $response = $this->wantsJson($request) ? new Response(status: 204) : redirect('/');

        // Not "cookies": that would also clear the device cookie and make the
        // next sign in look like a new device. The session itself is gone.
        $response->headers->set('Clear-Site-Data', '"cache", "storage"');

        return $response;
    }
}
