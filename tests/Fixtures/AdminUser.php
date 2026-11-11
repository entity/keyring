<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Database\Eloquent\Attributes\Table;

/**
 * A kind of user kept in the users table, as with single table inheritance.
 */
#[Table(name: 'users')]
class AdminUser extends User {}
