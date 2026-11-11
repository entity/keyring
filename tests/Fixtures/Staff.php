<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Keyring\Concerns\HasKeyring;

/**
 * A second kind of account, whose IDs overlap with the users'.
 */
#[Unguarded]
#[Table(name: 'staff')]
class Staff extends Authenticatable
{
    use HasKeyring;

    protected function casts(): array
    {
        return ['password' => 'hashed'];
    }
}
