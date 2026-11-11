<?php

declare(strict_types=1);

namespace Keyring\Http\Requests;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Keyring\Events\AccessRefused;

/**
 * Laravel's check that a verification link is the signed-in user's own,
 * which also puts on record a link that was someone else's, or for an
 * address the account no longer has. The answer is still Laravel's 403.
 */
class VerifyEmailRequest extends EmailVerificationRequest
{
    protected function failedAuthorization()
    {
        if (($user = $this->user()) instanceof Authenticatable) {
            AccessRefused::dispatch($user, 'email_verification', (string) $this->route('id'));
        }

        parent::failedAuthorization();
    }
}
