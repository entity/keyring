<?php

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent once the user's email address is verified. Built with whether that
 * just happened, or it already was.
 */
interface VerifiedResponse extends Responsable
{
    //
}
