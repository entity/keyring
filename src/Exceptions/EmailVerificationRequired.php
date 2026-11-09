<?php

namespace Keyring\Exceptions;

use LogicException;

/**
 * A setup that can't work, or isn't safe, without email verification.
 */
class EmailVerificationRequired extends LogicException
{
    /**
     * Laravel emails a verification link to MustVerifyEmail users when they
     * register, and the link needs the verification routes.
     */
    public static function forRegistration(string $model): self
    {
        return new self("[{$model}] implements MustVerifyEmail, so new users get a verification email, but email verification isn't on. Add Features::emailVerification() to the features in config/keyring.php.");
    }

    /**
     * With registration on, anyone can sign up with someone else's address.
     * A sign-in method they add would survive the real owner's password reset.
     */
    public static function forEnrollment(string $model): self
    {
        return new self("Registration is on, so anyone could sign up with someone else's address and add a sign-in method that outlives the owner's password reset. Users must verify their address first: implement MustVerifyEmail on [{$model}] and add Features::emailVerification() to the features in config/keyring.php.");
    }
}
