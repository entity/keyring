<?php

namespace Keyring\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Collection;
use Keyring\Sessions\RegisteredSession;

/**
 * Keeps track of signed-in sessions, separately from Laravel's session
 * driver, so they can be listed and revoked whether sessions live in files,
 * cookies, Redis or the database.
 */
interface SessionRegistry
{
    public function save(RegisteredSession $session): void;

    public function find(string $id): ?RegisteredSession;

    /**
     * Active sessions for the user, most recent first.
     *
     * @return Collection<int, RegisteredSession>
     */
    public function forUser(Authenticatable $user): Collection;

    /**
     * Change some of a session's fields (named as on RegisteredSession), and
     * only those, so a request can't write back a stale copy of the rest.
     *
     * @param  array<string, mixed>  $changes
     */
    public function update(string $id, array $changes): void;

    public function revoke(string $id): void;

    /**
     * Revoke every session of the user, except one (usually the current).
     */
    public function revokeAll(Authenticatable $user, ?string $except = null): int;

    public function revokeDevice(Authenticatable $user, string $deviceId): int;

    /**
     * Forget sessions that have expired or been revoked. Returns how many.
     */
    public function prune(): int;
}
