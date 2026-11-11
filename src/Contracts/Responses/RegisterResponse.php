<?php

declare(strict_types=1);

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent once a new user has registered and been signed in.
 */
interface RegisterResponse extends Responsable
{
    //
}
