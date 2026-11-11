<?php

declare(strict_types=1);

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
     * Move a session to a new record: store the new one, and have the old
     * one name it (replacedBy, replacedAt). A replaced record is no longer
     * an active session. Only one that is neither revoked nor replaced can
     * be, so of two requests replacing the same record at the same moment,
     * one is told false and its record isn't kept.
     *
     * With $revoke the old record is revoked in the same step, and no
     * request finds it replaced without being revoked.
     */
    public function replace(string $id, RegisteredSession $successor, bool $revoke = false): bool;

    /**
     * Revoke every session of the user, except one (usually the current).
     */
    public function revokeAll(Authenticatable $user, ?string $except = null): int;

    public function revokeDevice(Authenticatable $user, string $deviceId): int;

    /**
     * Forget sessions that have expired or been revoked. Returns how many.
     * A replaced one is kept until it expires: it's how its ID is known to
     * have been used up.
     */
    public function prune(): int;
}
