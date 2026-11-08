<?php

namespace Keyring\Http\Responses;

use Illuminate\Http\JsonResponse;
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
            return new JsonResponse(array_filter([
                'status' => $this->status,
                'message' => Keyring::statusMessage($this->status),
                'redirect' => $this->redirect,
                ...$this->data,
            ], fn (mixed $value) => $value !== null));
        }

        // Extra data goes under keyring.result: flashing "keyring" itself would
        // replace the session's verifications and registry ID.
        return ($this->redirect === null ? back() : redirect($this->redirect))
            ->with('status', $this->status)
            ->with($this->data === [] ? [] : ['keyring.result' => $this->data]);
    }
}
