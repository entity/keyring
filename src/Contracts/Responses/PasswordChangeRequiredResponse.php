<?php

declare(strict_types=1);

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when the user has to choose a new password before going on.
 */
interface PasswordChangeRequiredResponse extends Responsable
{
    //
}
