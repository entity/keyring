<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;

class DatabaseSessionRegistry implements SessionRegistry
{
    public function __construct(
        protected ConnectionInterface $connection,
        protected string $table = 'keyring_sessions',
    ) {}

    public function save(RegisteredSession $session): void
    {
        // Never clear revoked_at from a stale copy: a revocation that lands
        // between reading and saving a record must stick. So must the
        // record that replaced it.
        $row = $session->toArray();

        $this->query()->upsert([$row], ['id'], array_values(array_diff(array_keys($row), ['id', 'revoked_at', 'replaced_by', 'replaced_at'])));
    }

    public function find(string $id): ?RegisteredSession
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

    public function update(string $id, array $changes): void
    {
        $this->query()->where('id', $id)->update(RegisteredSession::columns($changes));
    }

    /**
     * Read on the database written to, then revoked only while it's still
     * as read: the update matches it unrevoked, so of two calls only the
     * one that changed the row returns it, and with the replacedBy it had,
     * so what's returned is what was revoked. A record replaced in between
     * is revoked all the same, and read again, holding the row this update
     * holds: inside a MySQL transaction a plain read would still see it as
     * it was before.
     */
    public function revoke(string $id): ?RegisteredSession
    {
        $row = $this->query()->useWritePdo()->find($id);
        $session = $row === null ? null : RegisteredSession::fromArray((array) $row);

        if ($session === null || $session->revokedAt !== null) {
            return null;
        }

        $now = now()->getTimestamp();
        $revoked = fn (Builder $query) => $query->where('id', $id)->whereNull('revoked_at')->update(['revoked_at' => $now]) === 1;

        if ($revoked($this->query()->where('replaced_by', $session->replacedBy))) {
            return $session->with(['revokedAt' => $now]);
        }

        // Revoked, replaced or gone since it was read. Only a replaced one
        // is left for this call to revoke.
        if (! $revoked($this->query())) {
            return null;
        }

        $row = $this->query()->useWritePdo()->lockForUpdate()->find($id);

        // Gone only if pruned in the moment since, outside a transaction.
        return $row === null ? $session->with(['revokedAt' => $now]) : RegisteredSession::fromArray((array) $row);
    }

    /**
     * The update only matches a record still in use, and holds its row until
     * the new record is stored. Of two requests at the same moment the
     * second waits, then matches nothing.
     */
    public function replace(string $id, RegisteredSession $successor, bool $revoke = false): bool
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

    public function revokeAll(Authenticatable $user, ?string $except = null): Collection
    {
        return $this->revokeFound($this->activeFor($user)->when($except, fn (Builder $query) => $query->where('id', '!=', $except)));
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return $this->revokeFound($this->activeFor($user)->where('device_id', $deviceId));
    }

    /**
     * Find the records, then revoke them by ID, a thousand at a time as
     * revokeEveryone() does, so a user with years of expired records that
     * were never pruned doesn't make one statement too big. Read from the
     * database written to: a replica that lags would hand back records
     * already revoked, or miss new ones. Rows are locked one by one, never
     * a range, so a sign in isn't held up or deadlocked.
     *
     * Every record this revokes is returned. The update matches nothing but
     * the IDs that were read, and every record read is returned, so nothing
     * can be revoked here without being returned. What's returned and wasn't
     * revoked here is only ever a record another call revoked in between,
     * which both then return: reported twice, never missed. A record saved
     * after the read is neither revoked nor returned, as if it had been
     * saved a moment after this ran. One replaced in between is revoked and
     * returned as it was read, without its replacedBy. Keyring's own callers
     * (Sessions::signOutEverywhere() and revokeDevice()) hold the user's row,
     * as a move to a new record does, so they never meet one.
     *
     * @return Collection<int, RegisteredSession>
     */
    protected function revokeFound(Builder $query): Collection
    {
        $now = now()->getTimestamp();

        $found = $query->useWritePdo()->get()->map(fn (object $row) => RegisteredSession::fromArray((array) $row));

        $found->pluck('id')->chunk(1000)->each(
            fn (Collection $ids) => $this->query()->whereIn('id', $ids->values())->whereNull('revoked_at')->update(['revoked_at' => $now]),
        );

        return $found->map(fn (RegisteredSession $session) => $session->with(['revokedAt' => $now]));
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

    protected function query(): Builder
    {
        return $this->connection->table($this->table);
    }
}
