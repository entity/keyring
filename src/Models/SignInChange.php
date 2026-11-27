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
 * "authenticator_changes.established_after", or its recovery codes: until
 * that long after, it can't do so again. And when its first password was
 * set from a session, which isn't established until that long after. One
 * per user, pruned once it no longer holds anything back.
 *
 * @property string $id
 * @property CarbonInterface|null $changed_at
 * @property CarbonInterface|null $password_set_at
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
            'password_set_at' => 'datetime',
        ];
    }

    /**
     * @return Builder<static>
     */
    public function prunable(): Builder
    {
        $before = Duration::ago(config('keyring.authenticator_changes.established_after'));

        return static::query()
            ->where(fn (Builder $query) => $query->whereNull('changed_at')->orWhere('changed_at', '<', $before))
            ->where(fn (Builder $query) => $query->whereNull('password_set_at')->orWhere('password_set_at', '<', $before));
    }
}
