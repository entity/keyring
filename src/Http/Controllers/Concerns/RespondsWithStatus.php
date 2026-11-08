<?php

namespace Keyring\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Lang;
use Keyring\Contracts\Responses\StatusResponse;

trait RespondsWithStatus
{
    /**
     * The response for an action, through the swappable StatusResponse.
     *
     * @param  array<string, mixed>  $data
     */
    protected function status(string $status, array $data = [], ?string $redirect = null): StatusResponse
    {
        return app(StatusResponse::class, ['status' => $status, 'data' => $data, 'redirect' => $redirect]);
    }

    /**
     * The flashed status as a message for a page to show.
     */
    protected function statusMessage(Request $request): ?string
    {
        $status = $request->session()->get('status');

        return is_string($status) && Lang::has($key = 'keyring::status.'.$status) ? __($key) : $status;
    }
}
