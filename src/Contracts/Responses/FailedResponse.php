<?php

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when a factor fails to verify.
 */
interface FailedResponse extends Responsable
{
    //
}
