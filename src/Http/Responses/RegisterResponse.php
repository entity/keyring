<?php

namespace Keyring\Http\Responses;

use Keyring\Contracts\Responses\RegisterResponse as RegisterResponseContract;

/**
 * Behaves like signing in. Bind your own to send new users somewhere else,
 * like onboarding.
 */
class RegisterResponse extends AuthenticatedResponse implements RegisterResponseContract
{
    //
}
