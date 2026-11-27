<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Illuminate\Auth\Access\AuthorizationException;
use Keyring\Enums\ImpersonationRefusal;

/**
 * Keyring::impersonate() wouldn't sign in as that user: Laravel answers it
 * with a 403, whatever the reason. $reason says why, for code of the app's
 * own. It's never ImpersonationRefusal::NotFound, which is only logged:
 * an ID nobody has is thrown as NotAllowed.
 */
class ImpersonationRefused extends AuthorizationException
{
    public function __construct(
        public readonly ImpersonationRefusal $reason,
    ) {
        parent::__construct(__('keyring::keyring.impersonation_refused'));
    }
}
