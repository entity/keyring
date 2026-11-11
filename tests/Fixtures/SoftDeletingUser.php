<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Database\Eloquent\SoftDeletes;

class SoftDeletingUser extends User
{
    use SoftDeletes;
}
