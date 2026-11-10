<?php

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when a session is ended for the user: it was revoked, timed out or
 * a risk response signed it out. Built with the reason.
 */
interface SignedOutResponse extends Responsable
{
    //
}
