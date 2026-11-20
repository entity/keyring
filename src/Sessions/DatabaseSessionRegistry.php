<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\SweepsSessions;
use Keyring\Enums\SessionEndReason;

class DatabaseSessionRegistry implements SessionRegistry, SweepsSessions
{
    public function __construct(
        protected ConnectionInterface $connection,
        protected string $table = 'keyring_sessions',
    ) {}

    public function save(#[\SensitiveParameter] RegisteredSession $session): void
    {
        // Never clear revoked_at from a stale copy: a revocation that lands
        // between reading and saving a record must stick. So must the
        // record that replaced it.
        $row = $session->toArray();

        // A record a session started on has no origin to write. Leaving the
        // column out keeps signing in working on a table that's still
        // waiting for the migration that adds it.
        if ($row['origin'] === null) {
            unset($row['origin']);
        }

        $this->query()->upsert([$row], ['id'], array_values(array_diff(array_keys($row), ['id', 'revoked_at', 'replaced_by', 'replaced_at'])));
    }

    public function find(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        $row = $this->query()->find($id);

        return $row === null ? null : RegisteredSession::fromArray((array) $row);
    }

    public function forUser(Authenticatable $user): Collection
    {
        return $this->activeFor($user)
            ->where('expires_at', '>', now()->getTimestamp())
            ->latest('last_activity_at')
            ->get()
            ->map(fn (object $row) => RegisteredSession::fromArray((array) $row));
    }

    public function update(#[\SensitiveParameter] string $id, array $changes): void
    {
        $this->query()->where('id', $id)->update(RegisteredSession::columns($changes));
    }

    /**
     * The row is read with a lock and revoked in the same transaction, so
     * nothing changes it in between: of two calls the second waits, then
     * finds it revoked and returns null. A locking read is always made on
     * the write connection, and sees the latest committed row even inside a
     * caller's MySQL transaction that took its snapshot earlier. It can't
     * deadlock with replace() or revokeEveryone(): this takes one lock (the
     * row, or on MySQL the gap where a missing one would be) and nothing
     * after it, so it never holds one while waiting for another.
     */
    public function revoke(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        return $this->connection->transaction(function () use ($id) {
            $row = $this->query()->lockForUpdate()->find($id);
            $session = $row === null ? null : RegisteredSession::fromArray((array) $row);

            if ($session === null || $session->revokedAt !== null) {
                return null;
            }

            $now = now()->getTimestamp();
            $this->query()->where('id', $id)->update(['revoked_at' => $now]);

            return $session->with(['revokedAt' => $now]);
        });
    }

    /**
     * The update only matches a record still in use, and holds its row until
     * the new record is stored. Of two requests at the same moment the
     * second waits, then matches nothing.
     */
    public function replace(#[\SensitiveParameter] string $id, #[\SensitiveParameter] RegisteredSession $successor, bool $revoke = false): bool
    {
        return $this->connection->transaction(function () use ($id, $successor, $revoke) {
            $now = now()->getTimestamp();

            $replaced = $this->query()->where('id', $id)->whereNull('revoked_at')->whereNull('replaced_by')->update([
                'replaced_by' => $successor->id,
                'replaced_at' => $now,
                ...$revoke ? ['revoked_at' => $now] : [],
            ]) === 1;

            if ($replaced) {
                $this->save($successor);
            }

            return $replaced;
        });
    }

    public function revokeAll(Authenticatable $user, #[\SensitiveParameter] ?string $except = null): Collection
    {
        return $this->revokeFound($this->activeFor($user)->when($except, fn (Builder $query) => $query->where('id', '!=', $except)));
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return $this->revokeFound($this->activeFor($user)->where('device_id', $deviceId));
    }

    /**
     * Find the records with a lock, then revoke them by ID in the same
     * transaction, a thousand at a time as revokeEveryone() does, so a user
     * with years of expired records that were never pruned doesn't make one
     * statement too big. A locking read is always made on the write
     * connection, and reads the latest committed rows, not the snapshot of
     * a caller's MySQL transaction that started earlier: a session signed
     * in since then is found and revoked. It takes the locks the single
     * UPDATE this used to be took (on MySQL, the user's range of the
     * index), so a sign in for this user waits until it's done, and the
     * rows can't change between the read and the update. So the records
     * returned are exactly the ones revoked, and the update matches what
     * the single UPDATE matched. Of two calls at once the second waits, and
     * then finds nothing left to revoke. Rows are read in ID order, so two
     * calls on PostgreSQL lock the rows they share in the same order.
     *
     * @return Collection<int, RegisteredSession>
     */
    protected function revokeFound(Builder $query): Collection
    {
        return $this->connection->transaction(function () use ($query) {
            $now = now()->getTimestamp();

            $found = $query->orderBy('id')->lockForUpdate()->get()->map(fn (object $row) => RegisteredSession::fromArray((array) $row));

            $found->pluck('id')->chunk(1000)->each(
                fn (Collection $ids) => $this->query()->whereIn('id', $ids->values())->whereNull('revoked_at')->whereNull('replaced_by')->update(['revoked_at' => $now]),
            );

            return $found->map(fn (RegisteredSession $session) => $session->with(['revokedAt' => $now]));
        });
    }

    /**
     * A thousand at a time, found first and then revoked by ID, until none
     * are left. A session moving to a new record holds its old one until the
     * new one is stored, so the round that comes to the old one waits, and
     * the next finds where it went. Replaced records are revoked with the
     * rest, which is what keeps the rounds coming. Rows are locked one by
     * one this way, never a range, so a sign in or a move isn't held up or
     * deadlocked. A session that started after this did is left alone, so
     * new sign ins can't keep it going. Each round reads from the database
     * it writes to: a replica that lags would keep handing back what the
     * last round revoked.
     */
    public function revokeEveryone(): void
    {
        $now = now()->getTimestamp();

        do {
            $ids = $this->query()
                ->useWritePdo()
                ->whereNull('revoked_at')
                ->where('authenticated_at', '<=', $now)
                ->where('expires_at', '>', $now)
                ->limit(1000)
                ->pluck('id');

            $this->query()->whereIn('id', $ids)->whereNull('revoked_at')->update(['revoked_at' => $now]);
        } while ($ids->isNotEmpty());
    }

    /**
     * With the sweep off, every record that has expired or been revoked
     * goes. With it on (Sweep::on), the sweep still has to end what has
     * timed out and announce what was revoked, so a record goes once it's
     * been announced, or once the sweep has given up on it. A replaced one
     * is never announced, and goes when it expires, either way.
     */
    public function prune(): int
    {
        $now = now()->getTimestamp();

        if (! Sweep::on() || ! $this->canSweep()) {
            return $this->query()
                ->where('expires_at', '<=', $now)
                ->orWhere(fn (Builder $query) => $query->whereNotNull('revoked_at')->whereNull('replaced_by'))
                ->delete();
        }

        return $this->query()
            ->where(fn (Builder $query) => $query->whereNotNull('replaced_by')->where('expires_at', '<=', $now))
            ->orWhere(fn (Builder $query) => $query->whereNotNull('revoked_at')->whereNull('replaced_by')->where(
                fn (Builder $query) => $query->whereNotNull('announced_at')->orWhere('revoked_at', '<=', $now - Sweep::GIVE_UP_AFTER),
            ))
            ->delete();
    }

    public function canSweep(): bool
    {
        return $this->connection instanceof Connection
            && $this->connection->getSchemaBuilder()->hasColumns($this->table, ['announced_at', 'end_reason', 'announce_attempts']);
    }

    /**
     * The records that have timed out are found on the write connection,
     * then locked by their IDs, in ID order as revokeAll() locks a user's,
     * so of two sweeps the second waits for the first, and the two never
     * take the same rows in a different order. Locking by ID takes the rows
     * alone, not a range of an index a sign-out is writing into, so a
     * sign-out can't deadlock with it on MySQL. A row someone else ended
     * meanwhile is left. Each of the rest is ended only if it has still
     * timed out, with one $now for the lot, and read back by its new
     * revoked_at while it's still locked: what's returned is exactly what
     * this call ended, and a request that used one a moment ago keeps it.
     */
    public function sweep(int $now, ?int $idle, ?int $rememberedIdle, int $limit): Collection
    {
        return $this->connection->transaction(function () use ($now, $idle, $rememberedIdle, $limit) {
            $found = $this->timingOut($this->query()->useWritePdo(), $now, $idle, $rememberedIdle)->orderBy('id')->limit($limit)->pluck('id');

            $open = $found->isEmpty() ? [] : $this->query()
                ->whereIn('id', $found->all())
                ->orderBy('id')
                ->lockForUpdate()
                ->get(['id', 'revoked_at', 'replaced_by'])
                ->filter(fn (object $row) => $row->revoked_at === null && $row->replaced_by === null)
                ->pluck('id')
                ->all();

            if ($open === []) {
                return new Collection;
            }

            $still = fn () => $this->query()->whereIn('id', $open)->whereNull('revoked_at')->whereNull('replaced_by');

            $still()->where('expires_at', '<=', $now)->update(['revoked_at' => $now, 'end_reason' => SessionEndReason::Expired->value]);
            $this->idling($still()->where('expires_at', '>', $now), $now, $idle, $rememberedIdle)->update(['revoked_at' => $now, 'end_reason' => SessionEndReason::Idle->value]);

            return $this->query()->useWritePdo()
                ->whereIn('id', $open)
                ->where('revoked_at', $now)
                ->whereIn('end_reason', [SessionEndReason::Expired->value, SessionEndReason::Idle->value])
                ->orderBy('id')
                ->get()
                ->map(fn (object $row) => new EndedSession(RegisteredSession::fromArray((array) $row), SessionEndReason::from($row->end_reason)));
        });
    }

    public function timedOut(int $now, ?int $idle, ?int $rememberedIdle): bool
    {
        return $this->timingOut($this->query()->useWritePdo(), $now, $idle, $rememberedIdle)->exists();
    }

    /**
     * A record revoked before this driver kept why has no reason, and is
     * announced again as plain "revoked".
     */
    public function unannounced(int $from, int $until, int $limit): Collection
    {
        return $this->query()->useWritePdo()
            ->whereNotNull('revoked_at')
            ->whereNull('replaced_by')
            ->whereNull('announced_at')
            ->where('revoked_at', '>', $from)
            ->where('revoked_at', '<=', $until)
            ->oldest('revoked_at')
            ->orderBy('id')
            ->limit($limit)
            ->get()
            ->map(fn (object $row) => new EndedSession(RegisteredSession::fromArray((array) $row), SessionEndReason::tryFrom((string) $row->end_reason) ?? SessionEndReason::Revoked));
    }

    /**
     * In a transaction of its own, so a failure (a table still waiting for
     * its migration) leaves the caller's transaction usable.
     */
    public function endedBecause(#[\SensitiveParameter] array $ids, SessionEndReason $reason): void
    {
        $this->connection->transaction(fn () => $this->query()->whereIn('id', $ids)->whereNull('end_reason')->update(['end_reason' => $reason->value]));
    }

    /**
     * Each failure counts against the record, and the last one it's allowed
     * marks it announced: a listener that always fails isn't run for it on
     * every sweep.
     */
    public function announced(#[\SensitiveParameter] array $announced, #[\SensitiveParameter] array $failed, int $at, int $attempts): void
    {
        $this->connection->transaction(function () use ($announced, $failed, $at, $attempts) {
            if ($announced !== []) {
                $this->query()->whereIn('id', $announced)->update(['announced_at' => $at]);
            }

            if ($failed !== []) {
                // Those on their last attempt first, so the rest can't be counted twice.
                $this->query()->whereIn('id', $failed)->where('announce_attempts', '>=', $attempts - 1)->increment('announce_attempts', 1, ['announced_at' => $at]);
                $this->query()->whereIn('id', $failed)->where('announce_attempts', '<', $attempts - 1)->increment('announce_attempts');
            }
        });
    }

    /**
     * Records that are neither revoked nor replaced, and have expired or
     * gone unused for too long: what the session middleware ends.
     */
    protected function timingOut(Builder $query, int $now, ?int $idle, ?int $rememberedIdle): Builder
    {
        return $query->whereNull('revoked_at')->whereNull('replaced_by')->where(
            fn (Builder $query) => $this->idling($query->where('expires_at', '<=', $now), $now, $idle, $rememberedIdle, or: true),
        );
    }

    /**
     * Unused for longer than the limit for its kind, as Sessions::idledOut()
     * has it: strictly more seconds than the limit since its last activity.
     */
    protected function idling(Builder $query, int $now, ?int $idle, ?int $rememberedIdle, bool $or = false): Builder
    {
        return $query->where(function (Builder $query) use ($now, $idle, $rememberedIdle) {
            $query->whereRaw('1 = 0')
                ->when($idle !== null, fn (Builder $query) => $query->orWhere(fn (Builder $query) => $query->where('remembered', false)->where('last_activity_at', '<', $now - (int) $idle)))
                ->when($rememberedIdle !== null, fn (Builder $query) => $query->orWhere(fn (Builder $query) => $query->where('remembered', true)->where('last_activity_at', '<', $now - (int) $rememberedIdle)));
        }, boolean: $or ? 'or' : 'and');
    }

    /**
     * The user's sessions that haven't been revoked or replaced.
     */
    protected function activeFor(Authenticatable $user): Builder
    {
        return $this->query()
            ->where('user_type', RegisteredSession::typeOf($user))
            ->where('user_id', (string) $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->whereNull('replaced_by');
    }

    /**
     * The connection the records are kept on, whose transactions decide
     * when a revocation holds (AnnouncingSessionRegistry).
     */
    public function connection(): ConnectionInterface
    {
        return $this->connection;
    }

    protected function query(): Builder
    {
        return $this->connection->table($this->table);
    }
}
