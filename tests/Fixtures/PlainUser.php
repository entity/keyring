<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Keyring\Concerns\HasKeyring;

/**
 * A user as the Quick Start has it: no MustVerifyEmail.
 */
#[Unguarded]
#[Hidden('password', 'remember_token')]
#[Table(name: 'users')]
class PlainUser extends Authenticatable
{
    use HasKeyring, Notifiable;

    protected function casts(): array
    {
        return ['password' => 'hashed'];
    }
}
