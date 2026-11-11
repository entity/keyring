<?php

declare(strict_types=1);

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when a route needs a sign-in method the user hasn't set up.
 */
interface EnrollmentRequiredResponse extends Responsable
{
    //
}
