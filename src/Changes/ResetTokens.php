<?php

namespace Keyring\Changes;

use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Password;
use Keyring\Features;

/**
 * The password reset links still out there for a user, kept by Laravel's
 * broker under the address they were sent to. A link sitting in a mailbox
 * must not outlive the password, the address or the account it was for.
 */
class ResetTokens
{
    /**
     * Without the feature there may be no token table, and nothing to forget.
     */
    public function forget(Model $user): void
    {
        if (! Features::enabled(Features::resetPasswords()) || ! $user instanceof CanResetPassword) {
            return;
        }

        $broker = Password::broker(config('keyring.passwords.broker'));

        if (method_exists($broker, 'deleteToken')) {
            $broker->deleteToken($user);
        }
    }
}
