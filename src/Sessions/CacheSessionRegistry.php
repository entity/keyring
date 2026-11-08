<?php

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;

/**
 * Keeps the registry in a cache store (Redis, Valkey, ...). No table needed.
 * Use a persistent store: if the cache is cleared, everyone is signed out.
 */
class CacheSessionRegistry implements SessionRegistry
{
    public function __construct(
        protected Repository $cache,
        protected string $prefix = 'keyring:sessions:',
    ) {}

    public function save(RegisteredSession $session): void
    {
        $this->cache->put($this->key($session->id), $session->toArray(), $this->ttl($session));

        $this->index($session->userId, function (array $ids) use ($session) {
            $ids[$session->id] = $session->expiresAt;

            return $ids;
        });
    }

    public function find(string $id): ?RegisteredSession
    {
        $data = $this->cache->get($this->key($id));

        return is_array($data) ? RegisteredSession::fromArray($data) : null;
    }

    public function forUser(Authenticatable $user): Collection
    {
        $now = now()->getTimestamp();

        return new Collection(array_keys($this->ids((string) $user->getAuthIdentifier())))
            ->map(fn (string $id) => $this->find($id))
            ->filter(fn (?RegisteredSession $session) => $session?->isActive($now))
            ->sortByDesc(fn (RegisteredSession $session) => $session->lastActivityAt)
            ->values();
    }

    public function touch(string $id, int $at): void
    {
        if ($session = $this->find($id)) {
            $this->cache->put($this->key($id), $session->with(['lastActivityAt' => $at])->toArray(), $this->ttl($session));
        }
    }

    public function revoke(string $id): void
    {
        if (($session = $this->find($id)) && $session->revokedAt === null) {
            $this->cache->put($this->key($id), $session->with(['revokedAt' => now()->getTimestamp()])->toArray(), $this->ttl($session));
        }
    }

    public function revokeAll(Authenticatable $user, ?string $except = null): int
    {
        return $this->forUser($user)
            ->reject(fn (RegisteredSession $session) => $session->id === $except)
            ->each(fn (RegisteredSession $session) => $this->revoke($session->id))
            ->count();
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): int
    {
        return $this->forUser($user)
            ->filter(fn (RegisteredSession $session) => $session->deviceId === $deviceId)
            ->each(fn (RegisteredSession $session) => $this->revoke($session->id))
            ->count();
    }

    /**
     * @return array<string, int>
     */
    protected function ids(string $userId): array
    {
        return $this->cache->get($this->prefix.'user:'.$userId, []);
    }

    /**
     * @param  callable(array<string, int>): array<string, int>  $change
     */
    protected function index(string $userId, callable $change): void
    {
        $update = function () use ($userId, $change) {
            $now = now()->getTimestamp();
            $ids = array_filter($change($this->ids($userId)), fn (int $expiresAt) => $expiresAt > $now);

            $this->cache->put($this->prefix.'user:'.$userId, $ids, max([0, ...$ids]) - $now + 60);
        };

        $this->cache->getStore() instanceof LockProvider
            ? $this->cache->getStore()->lock($this->prefix.'lock:'.$userId, 5)->block(5, $update)
            : $update();
    }

    protected function ttl(RegisteredSession $session): int
    {
        return max(60, $session->expiresAt - now()->getTimestamp() + 60);
    }

    protected function key(string $id): string
    {
        return $this->prefix.$id;
    }
}
