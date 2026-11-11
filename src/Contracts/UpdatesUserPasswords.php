<?php

namespace Keyring\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Your code, published to app/Actions/Keyring/UpdateUserPassword.php by
 * keyring:install.
 */
interface UpdatesUserPasswords
{
    /**
     * Validate and save a new password the signed-in user chose. Keyring
     * has already checked their current password, when they have one, and
     * afterwards signs out their other sessions (unless they asked not to)
     * and cancels pending email changes.
     *
     * @param  array<string, mixed>  $input
     */
    public function update(Authenticatable&Model $user, array $input): void;
}
