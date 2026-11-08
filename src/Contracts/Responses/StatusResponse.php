<?php

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent after every other action (a code sent, a device signed out, a
 * password changed...). Built with `status`, `data` and `redirect`.
 */
interface StatusResponse extends Responsable
{
    //
}
