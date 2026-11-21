<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Support\Collection;

/**
 * A session registry driver that keeps track of which ended sessions have
 * been announced, so keyring:sweep can end the ones that timed out with no
 * request to end them, and announce again any whose announcement was lost.
 * The database driver is one. The SessionRegistry contract doesn't need
 * it: a driver without it is announced as it ends sessions, and that's all.
 *
 * Not a contract yet: only the database driver keeps track this way, and
 * how it notes retries may change without an upgrade note.
 *
 * @internal
 */
interface SweepsSessions
{
    /**
     * Whether the store has what sweeping needs: on the database driver,
     * the columns its migration adds.
     */
    public function canSweep(): bool;

    /**
     * End up to $limit records the session middleware would end on their
     * next request, those that timed out longest ago first: past their
     * expiry, or unused for longer than $idle ($rememberedIdle for a
     * remembered one; null for no limit). Each is ended only if it still
     * has timed out as it's written, so a request that used it a moment ago
     * wins. Returns the records this call ended, as they now stand, with
     * why each ended, and whether more are left.
     *
     * @return array{ended: Collection<int, EndedSession>, more: bool}
     */
    public function sweep(int $now, ?int $idle, ?int $rememberedIdle, int $limit): array;

    /**
     * Up to $limit records revoked after $from and up to $until whose
     * announcement never went out, and that are due a try at $now, oldest
     * first, with why each ended, and whether more are left.
     *
     * @return array{ended: Collection<int, EndedSession>, more: bool}
     */
    public function unannounced(int $from, int $until, int $now, int $limit): array;

    /**
     * Note that these records were announced, and that a listener failed
     * for those, which are tried again later (Sweep::retryAfter). A driver
     * keeps why each record ended as it revokes it, with the reason in
     * force (AnnouncingSessionRegistry::reason).
     *
     * @param  list<string>  $announced
     * @param  list<string>  $failed
     */
    public function announced(#[\SensitiveParameter] array $announced, #[\SensitiveParameter] array $failed, int $at): void;

    /**
     * The moments everyone was signed out at (revokeEveryone), between $from
     * and $until, whose EveryoneSignedOut never went out, and that are due
     * a try at $now, latest first. A driver marks the records such a
     * sign-out ends so they aren't announced one by one, and counts them
     * announced once the event has gone out.
     *
     * @return list<int>
     */
    public function everyoneUnannounced(int $from, int $until, int $now): array;

    /**
     * Note how the EveryoneSignedOut for the sign-out made between $from and
     * $until went: announced, which settles every one up to $until, or to
     * be tried again later.
     */
    public function everyoneAnnounced(int $from, int $until, bool $announced, int $at): void;
}
