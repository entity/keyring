<?php

declare(strict_types=1);

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent after the user signs out.
 */
interface LogoutResponse extends Responsable
{
    //
}
