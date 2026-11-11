<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers\Concerns;

use Illuminate\Http\Request;
use Keyring\Contracts\Responses\StatusResponse;

/**
 * For controllers that keep the manager as $keyring.
 */
trait RespondsWithStatus
{
    /**
     * The response for an action, through the swappable StatusResponse.
     *
     * @param  array<string, mixed>  $data
     */
    protected function status(string $status, array $data = [], ?string $redirect = null): StatusResponse
    {
        return $this->keyring->response(StatusResponse::class, status: $status, data: $data, redirect: $redirect);
    }

    /**
     * The flashed status as a message for a page to show. Statuses that
     * aren't Keyring's (like the password broker's) are already messages,
     * and one that isn't text, flashed by the app for itself, is no message.
     */
    protected function statusMessage(Request $request): ?string
    {
        $status = $request->session()->get('status');

        return $this->keyring->statusMessage($status) ?? (is_string($status) ? $status : null);
    }
}
