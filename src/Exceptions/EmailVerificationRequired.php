<?php

declare(strict_types=1);

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
        return new self("[{$model}] implements MustVerifyEmail, so new users get a verification email, but there's no [verification.verify] route for its link. Add Features::emailVerification() to the features in config/keyring.php, or define the route yourself.");
    }

    /**
     * Registration that hides who has an account leaves new users signed
     * out until they follow the link sent to their address, so without
     * verification nobody who registers could ever sign in.
     */
    public static function forHiddenRegistration(?string $model = null): self
    {
        $model = $model === null || $model === '' ? 'your user model' : "[{$model}]";

        return new self("Registration answers the same whether or not an address has an account, and new users sign in once they've verified theirs. That needs email verification: implement MustVerifyEmail on {$model} and add Features::emailVerification() to the features in config/keyring.php. To tell visitors an address is taken and sign new users in straight away instead, set registration.reveal_taken to true there.");
    }

    /**
     * With registration on, anyone can sign up with someone else's address.
     * A sign-in method they add would survive the real owner's password reset.
     */
    public static function forEnrollment(string $model): self
    {
        return new self("Registration is on, so anyone could sign up with someone else's address and add a sign-in method that outlives the owner's password reset. Users must verify their address first: implement MustVerifyEmail on [{$model}] and add Features::emailVerification() to the features in config/keyring.php. If you prove addresses another way, say who may add one with Keyring::allowEnrollmentWhen().");
    }
}
