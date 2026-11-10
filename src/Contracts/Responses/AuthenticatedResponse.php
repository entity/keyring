<?php

namespace Keyring\Contracts\Responses;

use Illuminate\Contracts\Support\Responsable;

/**
 * Sent when a login or confirmation completes. Built with the pipeline's
 * `context` after a verification, and with nothing after registration.
 */
interface AuthenticatedResponse extends Responsable
{
    /**
     * The constructor arguments Keyring passes, by name.
     *
     * @var list<string>
     */
    public const array BUILT_WITH = ['context'];
}
