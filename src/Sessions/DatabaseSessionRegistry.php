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
        // between reading and saving a record must stick.
        $row = $session->toArray();

        $this->query()->upsert([$row], ['id'], array_values(array_diff(array_keys($row), ['id', 'revoked_at'])));
    }

    public function find(string $id): ?RegisteredSession
    {
        $row = $this->query()->find($id);

        return $row === null ? null : RegisteredSession::fromArray((array) $row);
    }

    public function forUser(Authenticatable $user): Collection
    {
        return $this->query()
            ->where('user_id', (string) $user->getAuthIdentifier())
            ->whereNull('revoked_at')
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

    public function revokeAll(Authenticatable $user, ?string $except = null): int
    {
        return $this->query()
            ->where('user_id', (string) $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->when($except, fn (Builder $query) => $query->where('id', '!=', $except))
            ->update(['revoked_at' => now()->getTimestamp()]);
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): int
    {
        return $this->query()
            ->where('user_id', (string) $user->getAuthIdentifier())
            ->where('device_id', $deviceId)
            ->whereNull('revoked_at')
            ->update(['revoked_at' => now()->getTimestamp()]);
    }

    public function prune(): int
    {
        return $this->query()
            ->where('expires_at', '<=', now()->getTimestamp())
            ->orWhereNotNull('revoked_at')
            ->delete();
    }

    protected function query(): Builder
    {
        return $this->connection->table($this->table);
    }
}
