<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Keyring\Support\Duration;
use Throwable;

/**
 * The sweep's settings, read in one place: keyring:sweep ends sessions that
 * have timed out with no request to end them, and announces again those
 * whose announcement was lost (database driver only). It's on when
 * "sessions.sweep_every" is set, and then pruning leaves what the sweep has
 * still to do.
 */
final class Sweep
{
    /** Default for "sessions.sweep_limit": how many records one run may end or announce. */
    public const int LIMIT = 1000;

    /** The most "sessions.sweep_limit" may be. */
    public const int MAX_LIMIT = 10000;

    /** How long a revoked record goes unannounced before the sweep announces it again: one still being announced isn't doubled. */
    public const int GRACE = 300;

    /** How long after its revocation the sweep keeps trying to announce a record. After that pruning may forget it. */
    public const int GIVE_UP_AFTER = 86400;

    /** The longest "sessions.sweep_every" may be, in minutes, well inside GIVE_UP_AFTER. */
    public const int LONGEST = 720;

    /**
     * Minutes between sweeps, or null when the sweep is off: unset, or not
     * a duration (problem() says so). A bare number counts seconds, and
     * under a minute is a minute. Longer than LONGEST is LONGEST.
     */
    public static function every(): ?int
    {
        $seconds = self::seconds();

        return $seconds === null || $seconds <= 0 ? null : min(self::LONGEST, max(1, intdiv($seconds, 60)));
    }

    /**
     * What's wrong with "sessions.sweep_every", if anything.
     */
    public static function problem(): ?string
    {
        $every = config('keyring.sessions.sweep_every');

        if ($every === null) {
            return null;
        }

        $seconds = self::seconds();

        return match (true) {
            $seconds === null => 'Keyring\'s sessions.sweep_every isn\'t a duration such as "5m" or "1h", so the sweep is off.',
            $seconds <= 0 => 'Keyring\'s sessions.sweep_every is zero, so the sweep is off.',
            $seconds > self::LONGEST * 60 => 'Keyring\'s sessions.sweep_every is longer than 12 hours, so the sweep runs every 12 hours: a revocation it misses for a day is given up on.',
            default => null,
        };
    }

    protected static function seconds(): ?int
    {
        $every = config('keyring.sessions.sweep_every');

        try {
            return is_string($every) || is_int($every) ? Duration::seconds($every) : null;
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * How long the scheduler may hold the sweep's "already running" lock
     * before it counts as left behind by a server that died: twice the
     * interval, at least ten minutes, at most six hours, so a crash costs a
     * few runs and never the day the sweep keeps trying for.
     */
    public static function lockFor(int $minutes): int
    {
        return min(360, max(10, 2 * $minutes));
    }

    /**
     * Seconds to wait before trying a failed announcement again, after its
     * $attempts-th try: GRACE, then doubling, until the day is out.
     */
    public static function retryAfter(int $attempts): int
    {
        return min(self::GIVE_UP_AFTER, self::GRACE * 2 ** min(20, max(0, $attempts - 1)));
    }

    public static function on(): bool
    {
        return self::every() !== null;
    }

    /**
     * The schedule for a sweep every so many minutes. A step that doesn't
     * divide the hour or the day runs at the steps that fit in it.
     */
    public static function cron(int $minutes): string
    {
        return $minutes < 60 ? "*/{$minutes} * * * *" : '0 */'.intdiv($minutes, 60).' * * *';
    }

    /**
     * The most one run ends, and the most it announces again: each.
     */
    public static function limit(): int
    {
        $limit = config('keyring.sessions.sweep_limit');

        return is_int($limit) && $limit > 0 ? min(self::MAX_LIMIT, $limit) : self::LIMIT;
    }
}
