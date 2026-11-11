<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Sessions\Sessions;

/**
 * The user's own sessions, straight from the registry, so they're there
 * whether or not the app keeps devices.
 */
class SessionController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
    ) {}

    /**
     * Sign out everywhere except here.
     */
    public function destroyOthers(Request $request): StatusResponse
    {
        $this->sessions->signOutOthers($request, $this->keyring->user());

        return $this->status('sessions-revoked');
    }
}
