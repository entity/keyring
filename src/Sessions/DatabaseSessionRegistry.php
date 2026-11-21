<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;
use Keyring\Support\WithoutBindings;

class DatabaseSessionRegistry implements SessionRegistry
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

        $this->withoutBindings(fn () => $this->query()->upsert([$row], ['id'], array_values(array_diff(array_keys($row), ['id', 'revoked_at', 'replaced_by', 'replaced_at']))));
    }

    public function find(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        $row = $this->withoutBindings(fn () => $this->query()->find($id));

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
        $this->withoutBindings(fn () => $this->query()->where('id', $id)->update(RegisteredSession::columns($changes)));
    }

    /**
     * The row is read with a lock and revoked in the same transaction, so
     * nothing changes it in between: of two calls the second waits, then
     * finds it revoked and returns null. The update only matches a record
     * that isn't revoked yet, as a second guard. A locking read is always
     * made on the write connection, and sees the latest committed row even
     * inside a caller's MySQL transaction that took its snapshot earlier. It
     * can't deadlock with replace() or revokeEveryone(): this takes one lock
     * (the row, or on MySQL the gap where a missing one would be) and
     * nothing after it, so it never holds one while waiting for another.
     */
    public function revoke(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        return $this->withoutBindings(fn () => $this->connection->transaction(function () use ($id) {
            $row = $this->query()->lockForUpdate()->find($id);
            $session = $row === null ? null : RegisteredSession::fromArray((array) $row);

            if ($session === null || $session->revokedAt !== null) {
                return null;
            }

            $now = now()->getTimestamp();
            $revoked = $this->query()->where('id', $id)->whereNull('revoked_at')->update(['revoked_at' => $now]) === 1;

            return $revoked ? $session->with(['revokedAt' => $now]) : null;
        }));
    }

    /**
     * The update only matches a record still in use, and holds its row until
     * the new record is stored. Of two requests at the same moment the
     * second waits, then matches nothing.
     */
    public function replace(#[\SensitiveParameter] string $id, #[\SensitiveParameter] RegisteredSession $successor, bool $revoke = false): bool
    {
        return $this->withoutBindings(fn () => $this->connection->transaction(function () use ($id, $successor, $revoke) {
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
        }));
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
        return $this->withoutBindings(fn () => $this->connection->transaction(function () use ($query) {
            $now = now()->getTimestamp();

            $found = $query->orderBy('id')->lockForUpdate()->get()->map(fn (object $row) => RegisteredSession::fromArray((array) $row));

            $found->pluck('id')->chunk(1000)->each(
                fn (Collection $ids) => $this->query()->whereIn('id', $ids->values())->whereNull('revoked_at')->whereNull('replaced_by')->update(['revoked_at' => $now]),
            );

            return $found->map(fn (RegisteredSession $session) => $session->with(['revokedAt' => $now]));
        }));
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

            $this->withoutBindings(fn () => $this->query()->whereIn('id', $ids)->whereNull('revoked_at')->update(['revoked_at' => $now]));
        } while ($ids->isNotEmpty());
    }

    public function prune(): int
    {
        return $this->query()
            ->where('expires_at', '<=', now()->getTimestamp())
            ->orWhere(fn (Builder $query) => $query->whereNotNull('revoked_at')->whereNull('replaced_by'))
            ->delete();
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

    /**
     * Run statements that name records by their IDs, and fail without them
     * (WithoutBindings). Wrapped around whole transactions, so Laravel's
     * own retries and rollbacks see the original.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $statements
     * @return TResult
     */
    protected function withoutBindings(Closure $statements): mixed
    {
        return WithoutBindings::run($statements);
    }

    protected function query(): Builder
    {
        return $this->connection->table($this->table);
    }
}
