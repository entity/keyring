<?php

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when a route needs the user to confirm it's them first (step-up).
 */
interface ConfirmationRequiredResponse extends Responsable
{
    //
}
