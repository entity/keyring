<?php

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when there have been too many attempts.
 */
interface LockoutResponse extends Responsable
{
    //
}
