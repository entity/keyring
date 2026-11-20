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

    /**
     * Revoke one record. Returns it as it now stands (revokedAt set), or
     * null when this call revoked nothing: there's no such record, or it was
     * revoked already. A record that was replaced but not revoked is revoked
     * all the same, and returned with its replacedBy, which says the session
     * carried on elsewhere. Of two calls revoking the same record at the
     * same moment, only one is given it.
     */
    public function revoke(string $id): ?RegisteredSession;

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
     * Returns the records this call revoked, each as it now stands.
     *
     * Every record a call revokes is in what it returns. Two calls at the
     * same moment may both return the same record, so a caller that reports
     * what ended may report one twice, never miss one.
     *
     * @return Collection<int, RegisteredSession>
     */
    public function revokeAll(Authenticatable $user, ?string $except = null): Collection;

    /**
     * Revoke the user's sessions on one device. Returns the records this
     * call revoked, as revokeAll() does.
     *
     * @return Collection<int, RegisteredSession>
     */
    public function revokeDevice(Authenticatable $user, string $deviceId): Collection;

    /**
     * Revoke every session of every user that signed in up to now, however
     * many records each has moved through since. One that is moving to a new
     * record as this runs is revoked there too, so "remember me" can't carry
     * it past this. A sign in after it starts a session as usual.
     */
    public function revokeEveryone(): void;

    /**
     * Forget sessions that have expired or been revoked. Returns how many.
     * A replaced one is kept until it expires: it's how its ID is known to
     * have been used up.
     */
    public function prune(): int;
}
