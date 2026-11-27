<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Illuminate\Auth\Access\AuthorizationException;

/**
 * Keyring::impersonate() wouldn't sign in as that user: Laravel answers it
 * with a 403. $reason says why, for code of the app's own: "not_allowed"
 * (Features::impersonation() is off, Keyring::allowImpersonationWhen()
 * said no or was never called, the user may not sign in, or isn't one
 * Keyring's guard loads), "self", "impersonating" (one at a time) or
 * "unregistered" (the impersonator's session has no record to come back to).
 */
class ImpersonationRefused extends AuthorizationException
{
    public function __construct(
        public readonly string $reason,
    ) {
        parent::__construct(__('keyring::keyring.impersonation_refused'));
    }
}
