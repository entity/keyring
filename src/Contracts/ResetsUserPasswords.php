<?php

namespace Keyring\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Your code, published to app/Actions/Keyring/ResetUserPassword.php by
 * keyring:install.
 */
interface ResetsUserPasswords
{
    /**
     * Validate and save a new password from a reset link. Keyring then
     * signs out every session, cancels pending email changes and lifts
     * risk locks.
     *
     * @param  array<string, mixed>  $input
     */
    public function reset(Authenticatable&Model $user, array $input): void;
}
