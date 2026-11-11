<?php

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

    public function revoke(string $id): void
    {
        $this->query()->where('id', $id)->whereNull('revoked_at')->update(['revoked_at' => now()->getTimestamp()]);
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

    public function revokeAll(Authenticatable $user, ?string $except = null): int
    {
        return $this->activeFor($user)
            ->when($except, fn (Builder $query) => $query->where('id', '!=', $except))
            ->update(['revoked_at' => now()->getTimestamp()]);
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): int
    {
        return $this->activeFor($user)
            ->where('device_id', $deviceId)
            ->update(['revoked_at' => now()->getTimestamp()]);
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
        return $this->query()->where('user_id', (string) $user->getAuthIdentifier())->whereNull('revoked_at')->whereNull('replaced_by');
    }

    protected function query(): Builder
    {
        return $this->connection->table($this->table);
    }
}
