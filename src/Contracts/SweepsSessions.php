<?php

declare(strict_types=1);

namespace Keyring\Contracts;

use Illuminate\Support\Collection;
use Keyring\Enums\SessionEndReason;
use Keyring\Sessions\EndedSession;

/**
 * A session registry driver that keeps track of which ended sessions have
 * been announced, so keyring:sweep can end the ones that timed out with no
 * request to end them, and announce again any whose announcement was lost.
 * The database driver is one. The SessionRegistry contract doesn't need
 * it: a driver without it is announced as it ends sessions, and that's all.
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
     * next request: past their expiry, or unused for longer than $idle
     * ($rememberedIdle for a remembered one; null for no limit). Each is
     * ended only if it still has timed out as it's written, so a request
     * that used it a moment ago wins. Returns the records this call ended,
     * as they now stand, with why each ended.
     *
     * @return Collection<int, EndedSession>
     */
    public function sweep(int $now, ?int $idle, ?int $rememberedIdle, int $limit): Collection;

    /**
     * Whether any record has timed out and is still to be ended.
     */
    public function timedOut(int $now, ?int $idle, ?int $rememberedIdle): bool;

    /**
     * Up to $limit records revoked between $from and $until whose
     * announcement never went out, oldest first, with why each ended.
     *
     * @return Collection<int, EndedSession>
     */
    public function unannounced(int $from, int $until, int $limit): Collection;

    /**
     * Keep why these records ended, for announcing them again.
     *
     * @param  list<string>  $ids
     */
    public function endedBecause(#[\SensitiveParameter] array $ids, SessionEndReason $reason): void;

    /**
     * Note that these records were announced, and that a listener failed
     * for those. One that has failed $attempts times counts as announced.
     *
     * @param  list<string>  $announced
     * @param  list<string>  $failed
     */
    public function announced(#[\SensitiveParameter] array $announced, #[\SensitiveParameter] array $failed, int $at, int $attempts): void;
}
