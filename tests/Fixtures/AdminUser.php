<?php

namespace Keyring\Tests\Fixtures;

/**
 * A kind of user kept in the users table, as with single table inheritance.
 */
class AdminUser extends User
{
    protected $table = 'users';
}
