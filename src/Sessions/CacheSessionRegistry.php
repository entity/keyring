<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;
use Keyring\Exceptions\PartialRevocation;
use Throwable;

/**
 * Keeps the registry in a cache store (Redis, Valkey, ...). No table needed.
 * Use a persistent store: if the cache is cleared, everyone is signed out.
 *
 * Revocations live in their own key that saves never write, so a request
 * saving a stale copy of its session can't undo a revocation. What replaced
 * a record is kept the same way.
 *
 * The cache can't list every user's records, so signing everyone out is one
 * more key: the moment up to which every session counts as revoked.
 */
class CacheSessionRegistry implements SessionRegistry
{
    public function __construct(
        protected Repository $cache,
        protected string $prefix = 'keyring:sessions:',
    ) {}

    /**
     * That a record was revoked or replaced is kept twice: in a key of its
     * own, which a stale copy saved over the record can't undo, and in the
     * record, so a store that drops one of the keys and keeps the other
     * doesn't bring the session back. What the record already says is kept
     * when the copy being saved doesn't know it.
     */
    public function save(#[\SensitiveParameter] RegisteredSession $session): void
    {
        $stored = $this->cache->get($this->key($session->id));
        $data = $session->toArray();

        foreach (['revoked_at', 'replaced_by', 'replaced_at'] as $ended) {
            $data[$ended] ??= is_array($stored) ? ($stored[$ended] ?? null) : null;
        }

        $this->cache->put($this->key($session->id), $data, $this->ttl($session));

        if ($session->revokedAt !== null) {
            $this->cache->add($this->revokedKey($session->id), $session->revokedAt, $this->ttl($session));
        }

        $this->index($this->owner($session), function (array $ids) use ($session) {
            $ids[$session->id] = $session->expiresAt;

            return $ids;
        });
    }

    public function find(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        $found = $this->cache->many([$this->key($id), $this->revokedKey($id), $this->replacedKey($id), $this->everyoneKey()]);
        $data = $found[$this->key($id)] ?? null;

        // A record from before records said whose table their ID is one of
        // can't be told apart from another model's, so it's no session.
        if (! is_array($data) || ! is_string($data['user_type'] ?? null)) {
            return null;
        }

        // A record carries the time its session signed in from one record to
        // the next, so everyone who was signed out stays signed out.
        $everyone = $found[$this->everyoneKey()] ?? null;

        return RegisteredSession::fromArray([
            ...$data,
            'revoked_at' => $found[$this->revokedKey($id)] ?? $data['revoked_at'] ?? ($everyone !== null && $data['authenticated_at'] <= $everyone ? $everyone : null),
            'replaced_by' => $found[$this->replacedKey($id)]['by'] ?? $data['replaced_by'] ?? null,
            'replaced_at' => $found[$this->replacedKey($id)]['at'] ?? $data['replaced_at'] ?? null,
        ]);
    }

    public function forUser(Authenticatable $user): Collection
    {
        $now = now()->getTimestamp();

        return new Collection(array_keys($this->ids($this->ownerKey(RegisteredSession::typeOf($user), (string) $user->getAuthIdentifier()))))
            ->map(fn (string $id) => $this->find($id))
            ->filter(fn (?RegisteredSession $session) => $session !== null && $session->belongsTo($user) && $session->isActive($now))
            ->sortByDesc(fn (RegisteredSession $session) => $session->lastActivityAt)
            ->values();
    }

    /**
     * The cache has no partial writes, so this reads and writes the record.
     * Revocations live in their own key, so this can never undo one.
     */
    public function update(#[\SensitiveParameter] string $id, array $changes): void
    {
        if ($session = $this->find($id)) {
            $this->save($session->with($changes));
        }
    }

    /**
     * Records expire with their TTL.
     */
    public function prune(): int
    {
        return 0;
    }

    /**
     * add() only writes a key that isn't there, so of two calls only one
     * revokes the record and returns it. One found revoked already, by its
     * own keys or by signing everyone out, returns null, and has what says
     * so written again in both places, with the time it already has: a
     * store that dropped one of them gets it back, and one only the
     * "everyone" key covered stays revoked without it.
     */
    public function revoke(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        $session = $this->find($id);

        if ($session === null) {
            return null;
        }

        if ($session->revokedAt !== null) {
            $this->cache->add($this->revokedKey($id), $session->revokedAt, $this->ttl($session));
            $this->stamp($session, ['revoked_at' => $session->revokedAt]);

            return null;
        }

        $now = now()->getTimestamp();

        // Lost to another call since find(), which stamps the record itself.
        if (! $this->cache->add($this->revokedKey($id), $now, $this->ttl($session))) {
            return null;
        }

        // The revoked key is what revokes it, and it's written. Had the
        // copy in the record failing undone this call, the record would be
        // revoked with nobody told: the next call finds it revoked already.
        try {
            $this->stamp($session, ['revoked_at' => $now]);
        } catch (Throwable $e) {
            rescue(fn () => report($e), report: false);
        }

        return $session->with(['revokedAt' => $now]);
    }

    /**
     * Write into the record what its own keys say ended it.
     *
     * @param  array<string, mixed>  $ended
     */
    protected function stamp(#[\SensitiveParameter] RegisteredSession $session, array $ended): void
    {
        $stored = $this->cache->get($this->key($session->id));

        if (is_array($stored)) {
            $this->cache->put($this->key($session->id), [...$stored, ...$ended], $this->ttl($session));
        }
    }

    /**
     * add() only writes a key that isn't there, which is what lets one of
     * two requests through. The new record is stored before that, so a
     * request that finds the old one replaced always finds what replaced it.
     * A revocation that landed in the meantime wins: the new record goes.
     */
    public function replace(#[\SensitiveParameter] string $id, #[\SensitiveParameter] RegisteredSession $successor, bool $revoke = false): bool
    {
        $session = $this->find($id);

        if ($session === null || $session->revokedAt !== null || $session->replacedBy !== null) {
            return false;
        }

        $this->save($successor);

        $now = now()->getTimestamp();
        $ttl = $this->ttl($session);

        // Revoked before it's replaced, so it's never found replaced only.
        $replaced = (! $revoke || $this->cache->add($this->revokedKey($id), $now, $ttl))
            && $this->cache->add($this->replacedKey($id), ['by' => $successor->id, 'at' => $now], $ttl)
            && ($revoke || $this->cache->missing($this->revokedKey($id)));

        if (! $replaced) {
            // Only when another request revoked or replaced it since find().
            $this->cache->forget($this->key($successor->id)); // @codeCoverageIgnore
        } else {
            $this->stamp($session, ['replaced_by' => $successor->id, 'replaced_at' => $now, ...$revoke ? ['revoked_at' => $now] : []]);
        }

        // A replaced record is found by its ID, and never listed again.
        $this->index($this->owner($session), fn (array $ids) => array_diff_key($ids, [($replaced ? $id : $successor->id) => true]));

        return $replaced;
    }

    public function revokeAll(Authenticatable $user, #[\SensitiveParameter] ?string $except = null): Collection
    {
        return $this->revokeWhere($user, fn (RegisteredSession $session) => $session->id !== $except);
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return $this->revokeWhere($user, fn (RegisteredSession $session) => $session->deviceId === $deviceId);
    }

    public function revokeEveryone(): void
    {
        $this->cache->forever($this->everyoneKey(), now()->getTimestamp());
    }

    /**
     * Each record is revoked by revoke(), so what's returned is what this
     * call revoked: one another call got to first is left out. A record
     * that fails doesn't stop the rest. Once they've all been tried, the
     * first failure is thrown, in a PartialRevocation that carries what
     * was revoked, so those are still announced.
     *
     * @param  Closure(RegisteredSession): bool  $callback
     * @return Collection<int, RegisteredSession>
     */
    protected function revokeWhere(Authenticatable $user, Closure $callback): Collection
    {
        $failure = null;

        $revoked = $this->forUser($user)
            ->filter($callback)
            ->map(function (RegisteredSession $session) use (&$failure) {
                try {
                    return $this->revoke($session->id);
                } catch (Throwable $e) {
                    $failure ??= $e;

                    return null;
                }
            })
            ->filter()
            ->values();

        if ($failure !== null) {
            throw new PartialRevocation($revoked, $failure);
        }

        return $revoked;
    }

    /**
     * What a user's list of sessions is kept under: the model and the ID,
     * since two user models can have the same IDs.
     */
    protected function owner(RegisteredSession $session): string
    {
        return $this->ownerKey($session->userType, $session->userId);
    }

    protected function ownerKey(string $userType, string $userId): string
    {
        return sha1($userType.'|'.$userId);
    }

    /**
     * @return array<string, int>
     */
    protected function ids(string $owner): array
    {
        return $this->cache->get($this->prefix.'user:'.$owner, []);
    }

    /**
     * @param  callable(array<string, int>): array<string, int>  $change
     */
    protected function index(string $owner, callable $change): void
    {
        $update = function () use ($owner, $change) {
            $now = now()->getTimestamp();
            $ids = array_filter($change($this->ids($owner)), fn (int $expiresAt) => $expiresAt > $now);

            $this->cache->put($this->prefix.'user:'.$owner, $ids, max([0, ...$ids]) - $now + 60);
        };

        $this->cache->getStore() instanceof LockProvider
            ? $this->cache->getStore()->lock($this->prefix.'lock:'.$owner, 5)->block(5, $update)
            : $update();
    }

    protected function ttl(RegisteredSession $session): int
    {
        return max(60, $session->expiresAt - now()->getTimestamp() + 60);
    }

    protected function key(#[\SensitiveParameter] string $id): string
    {
        return $this->prefix.$id;
    }

    /**
     * Revocations live in their own key, so saving a stale copy of the
     * record can never undo one.
     */
    protected function revokedKey(#[\SensitiveParameter] string $id): string
    {
        return $this->key($id).':revoked';
    }

    protected function replacedKey(#[\SensitiveParameter] string $id): string
    {
        return $this->key($id).':replaced';
    }

    /**
     * When everyone was last signed out (revokeEveryone). No session's ID
     * has a colon in it, so this is never mistaken for a record.
     */
    protected function everyoneKey(): string
    {
        return $this->prefix.'everyone:revoked';
    }
}
