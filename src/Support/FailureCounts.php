<?php

declare(strict_types=1);

namespace Keyring\Support;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Keyring\KeyringManager;
use Keyring\Models\Authenticator;
use Keyring\Models\FailureCount;
use Keyring\Pipeline\ConsecutiveLimit;

/**
 * The failures in a row behind a ConsecutiveLimit, in the database.
 *
 * Every change is one statement that checks as it writes, so two requests
 * can't both take the last failure the cap allows, and nothing holds a lock
 * while a proof is being checked.
 *
 * A name nobody has runs the same statements against a row that can't
 * exist, so a guess at it costs the database what a guess at a real one
 * does.
 */
class FailureCounts
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Whether the authenticator is refused for the attempt's kind of
     * browser. Keeps the row it read, which says what there is to add to
     * or to clear.
     */
    public function refuses(ConsecutiveLimit $limit): bool
    {
        $limit->count = $this->query($limit)->first();

        return $limit->count?->refuses($limit) ?? false;
    }

    /**
     * Count the attempt before its proof is looked at, and say whether it
     * may go ahead. With failures on record for its kind of browser, every
     * attempt is counted this way, so those that overlap can't all be
     * checked on the last failure the cap allows.
     *
     * With none there's nothing to write, and nothing a success would have
     * to clear: an ordinary sign in costs one read, and the attempt is
     * counted if it fails. A run can only begin with as many attempts at
     * once as the per-minute limits let through.
     */
    public function reserve(ConsecutiveLimit $limit): bool
    {
        if ($limit->failures() === 0) {
            return true;
        }

        if ($limit->reserved = $this->increment($limit)) {
            return true;
        }

        // Nothing to add to. Either it's refused by now, or a success or a
        // reset has cleared the row since it was read. Only another request
        // can do either in between, so the race tests are what reach this.
        // @codeCoverageIgnoreStart
        if ($this->query($limit)->exists()) {
            return false;
        }

        $limit->count = null;

        return true;
        // @codeCoverageIgnoreEnd
    }

    /**
     * The attempt failed. Count it if it wasn't counted going in, then mark
     * the authenticator refused if that used up what the attempt's kind of
     * browser may fail, or "lock_after" says to hold it. Returns whether
     * this failure was the one that did.
     */
    public function failed(ConsecutiveLimit $limit, bool $hold = false): bool
    {
        if (! $limit->reserved) {
            $this->count($limit);
        }

        return $this->query($limit)
            ->whereNull($limit->lockColumn())
            ->unless($hold, fn (Builder $query) => $query->spentBy($limit))
            ->update([$limit->lockColumn() => now()]) > 0;
    }

    /**
     * The attempt succeeded, which clears what its own kind of browser had
     * failed. Nothing is written when there was nothing to clear.
     */
    public function succeeded(ConsecutiveLimit $limit): void
    {
        if ($limit->failures() === 0) {
            return;
        }

        // The whole row when nothing else is on it, so the table only holds
        // authenticators someone is failing at.
        $deleted = $this->query($limit)
            ->where($limit->known ? 'failures' : 'known_failures', 0)
            ->whereNull(['locked_at', 'known_locked_at'])
            ->delete();

        if ($deleted === 0) {
            $this->query($limit)->update([$limit->column() => 0]);
        }
    }

    /**
     * Give back a count taken for an attempt that neither failed nor
     * succeeded: one that didn't validate, say, or that another limit
     * refused.
     */
    public function release(ConsecutiveLimit $limit): void
    {
        if ($limit->reserved) {
            $this->query($limit)->where($limit->column(), '>', 0)->decrement($limit->column());

            $limit->reserved = false;
        }
    }

    /**
     * Forget the user's failures on these factors, which lets them use
     * whichever of them was refused.
     *
     * @param  list<string>  $factors
     */
    public function clear(Authenticatable&Model $user, array $factors): void
    {
        $this->keyring->failureCountModel()::query()->ownedBy($user)->whereIn('factor', $factors)->delete();
    }

    /**
     * Forget the failures on an authenticator that's being removed, so one
     * added in its place starts from nothing.
     */
    public function forget(Authenticator $authenticator): void
    {
        $this->keyring->failureCountModel()::query()
            ->where('authenticatable_type', $authenticator->getAttribute('authenticatable_type'))
            ->where('authenticatable_id', $authenticator->getAttribute('authenticatable_id'))
            ->where('authenticator', $authenticator->id)
            ->delete();
    }

    /**
     * Count a failure that wasn't counted going in. The first of a run
     * starts the row, and two at once can't both: the second finds the
     * first's and adds to it. Nobody's name has no row to start.
     */
    protected function count(ConsecutiveLimit $limit): void
    {
        if ($limit->user === null || $limit->count !== null) {
            $this->increment($limit);

            return;
        }

        $count = $this->keyring->failureCountModel()::query()->createOrFirst([
            'authenticatable_type' => $limit->user->getMorphClass(),
            'authenticatable_id' => $limit->user->getKey(),
            'authenticator' => $limit->authenticator,
        ], [
            'factor' => $limit->factor,
            $limit->column() => 1,
        ]);

        if (! $count->wasRecentlyCreated) {
            $this->increment($limit);
        }
    }

    /**
     * Add a failure, if the attempt's kind of browser has one left to make.
     */
    protected function increment(ConsecutiveLimit $limit): bool
    {
        return $this->query($limit)->allowing($limit)->increment($limit->column()) > 0;
    }

    /**
     * The limit's row. Nobody's name has none, and its query finds none,
     * through the same index a real one's uses.
     *
     * @return Builder<FailureCount>
     */
    protected function query(ConsecutiveLimit $limit): Builder
    {
        $query = $this->keyring->failureCountModel()::query()->where('authenticator', $limit->authenticator);

        return $limit->user === null
            ? $query->where('authenticatable_type', '')->whereNull('authenticatable_id')
            : $query->ownedBy($limit->user);
    }
}
