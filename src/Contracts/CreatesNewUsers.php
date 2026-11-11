<?php

declare(strict_types=1);

namespace Keyring\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Validation\ValidationException;

/**
 * Your registration logic. Published to app/Actions/Keyring/CreateNewUser.php
 * by keyring:install.
 */
interface CreatesNewUsers
{
    /**
     * Validate a registration and return what create() needs. Don't check
     * here whether the address is taken: Keyring does, after this has passed,
     * and by default answers the same way either way, so nobody can use the
     * form to find out who has an account.
     *
     * @param  array<string, mixed>  $input
     * @return array<string, mixed>
     *
     * @throws ValidationException
     */
    public function validate(array $input): array;

    /**
     * Create the user from what validate() returned. Keyring only calls
     * this for an address nobody has.
     *
     * @param  array<string, mixed>  $input
     */
    public function create(array $input): Authenticatable&Model;
}
