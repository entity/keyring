<?php

declare(strict_types=1);

namespace Keyring\Models;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Eloquent\Attributes\Unguarded;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Model;
use Keyring\Models\Concerns\BelongsToUser;
use Keyring\Pipeline\ConsecutiveLimit;

/**
 * Failures in a row on one of an account's authenticators, and whether they
 * have disabled it. Kept in the database, so clearing the cache can't bring
 * a disabled authenticator back.
 *
 * Browsers the account has signed in from are counted beside everyone else
 * on the one row, so the two share the cap. A row only exists while there's
 * something to remember, and is never pruned: it goes when a success, a
 * password reset or Keyring::unlock() clears it, or with its authenticator
 * or its user.
 *
 * @property string $id
 * @property string $factor
 * @property string $authenticator
 * @property int $failures
 * @property int $known_failures
 * @property CarbonInterface|null $locked_at
 * @property CarbonInterface|null $known_locked_at
 */
#[Table('keyring_failure_counts')]
#[Unguarded]
class FailureCount extends Model
{
    use BelongsToUser, HasUlids;

    protected function casts(): array
    {
        return [
            'failures' => 'integer',
            'known_failures' => 'integer',
            'locked_at' => 'datetime',
            'known_locked_at' => 'datetime',
        ];
    }

    /**
     * Whether the authenticator is refused for the limit's kind of browser.
     */
    public function refuses(ConsecutiveLimit $limit): bool
    {
        return $this->getAttribute($limit->lockColumn()) !== null || $this->usedUpBy($limit);
    }

    /**
     * Whether the limit's kind of browser has no failures left to make.
     */
    public function usedUpBy(ConsecutiveLimit $limit): bool
    {
        return $limit->cap !== null && (
            $this->failures + $this->known_failures >= $limit->cap || $this->getAttribute($limit->column()) >= $limit->share
        );
    }

    /**
     * Rows that would let the limit's kind of browser fail once more. The
     * same test as refuses(), for the database to make as it counts.
     *
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function allowing(Builder $query, ConsecutiveLimit $limit): void
    {
        $query->whereNull($limit->lockColumn())->unless($limit->cap === null, fn (Builder $query) => $query
            ->whereRaw('failures + known_failures < ?', [$limit->cap])
            ->where($limit->column(), '<', $limit->share));
    }

    /**
     * Rows where the limit's kind of browser has no failures left to make.
     * None, without a cap.
     *
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function spentBy(Builder $query, ConsecutiveLimit $limit): void
    {
        $query->where(fn (Builder $query) => $limit->cap === null ? $query->whereRaw('1 = 0') : $query
            ->whereRaw('failures + known_failures >= ?', [$limit->cap])
            ->orWhere($limit->column(), '>=', $limit->share));
    }
}
