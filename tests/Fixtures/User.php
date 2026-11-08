<?php

namespace Keyring\Tests\Fixtures;

use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Keyring\Concerns\HasKeyring;

#[Unguarded]
#[Hidden('password', 'remember_token')]
class User extends Authenticatable
{
    use HasKeyring, Notifiable;

    protected $table = 'users';

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
}
