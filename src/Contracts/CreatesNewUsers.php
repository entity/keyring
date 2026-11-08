<?php

namespace Keyring\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Your registration logic. Published to app/Actions/Keyring/CreateNewUser.php
 * by keyring:install.
 */
interface CreatesNewUsers
{
    /**
     * Validate and create a newly registered user.
     *
     * @param  array<string, mixed>  $input
     */
    public function create(array $input): Authenticatable&Model;
}
