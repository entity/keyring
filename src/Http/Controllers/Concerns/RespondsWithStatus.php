<?php

namespace Keyring\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Facades\Keyring;

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
     * The flashed status as a message for a page to show. Statuses that
     * aren't Keyring's (like the password broker's) are already messages.
     */
    protected function statusMessage(Request $request): ?string
    {
        $status = $request->session()->get('status');

        return Keyring::statusMessage($status) ?? $status;
    }
}
