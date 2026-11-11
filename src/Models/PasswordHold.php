<?php

namespace Keyring\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Keyring\Models\Concerns\BelongsToUser;

/**
 * A user who has to choose a new password before going on, because there's
 * reason to think the one they have is known to someone else. One per user,
 * kept until the password changes.
 *
 * @property string $id
 * @property string|null $reason
 * @property CarbonInterface|null $created_at
 */
#[Table('keyring_password_holds')]
#[Unguarded]
#[Hidden('authenticatable_type', 'authenticatable_id')]
class PasswordHold extends Model
{
    use BelongsToUser, HasUlids;
}
