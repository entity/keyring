<?php

declare(strict_types=1);

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
use Illuminate\Support\Arr;
use Keyring\Contracts\Responses\StatusResponse as StatusResponseContract;
use Keyring\Facades\Keyring;

class StatusResponse implements StatusResponseContract
{
    use ChoosesFormat;

    /**
     * @param  string  $status  a slug such as "device-revoked", with its message in keyring::status
     * @param  array<string, mixed>  $data
     * @param  string|null  $redirect  where to go instead of back
     */
    public function __construct(
        public readonly string $status,
        public readonly array $data = [],
        public readonly ?string $redirect = null,
    ) {}

    public function toResponse($request)
    {
        if ($this->wantsJson($request)) {
            return new JsonResponse(Arr::whereNotNull([
                'status' => $this->status,
                'message' => Keyring::statusMessage($this->status),
                'redirect' => $this->redirect,
                ...$this->data,
            ]));
        }

        // Extra data goes under keyring.result: flashing "keyring" itself would
        // replace the session's verifications and registry ID.
        return ($this->redirect === null ? back() : redirect($this->redirect))
            ->with('status', $this->status)
            ->with($this->data === [] ? [] : ['keyring.result' => $this->data]);
    }
}
