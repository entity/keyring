<?php

declare(strict_types=1);

namespace Keyring\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Keyring\Models\Concerns\BelongsToUser;
use Keyring\Support\Duration;

/**
 * When an account last lost or replaced a sign-in method it had for
 * "authenticator_changes.established_after", or its recovery codes. Until
 * that long after, it can't do so again. One per user, pruned once it no
 * longer holds anything back.
 *
 * @property string $id
 * @property CarbonInterface $changed_at
 */
#[Table('keyring_sign_in_changes')]
#[Unguarded]
#[Hidden('authenticatable_type', 'authenticatable_id')]
class SignInChange extends Model
{
    use BelongsToUser, HasUlids, MassPrunable;

    protected function casts(): array
    {
        return [
            'changed_at' => 'datetime',
        ];
    }

    /**
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        return static::query()->where('changed_at', '<', Duration::ago(config('keyring.authenticator_changes.established_after')));
    }
}
