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

    /** How long a revoked record goes unannounced before the sweep announces it again: one still being announced isn't doubled. */
    public const int GRACE = 300;

    /** How long after its revocation the sweep keeps trying to announce a record. After that pruning may forget it. */
    public const int GIVE_UP_AFTER = 86400;

    /** How many announcements a listener may fail before the record counts as announced. */
    public const int ATTEMPTS = 3;

    /**
     * Minutes between sweeps, or null when the sweep is off, as it is for
     * anything that isn't a duration.
     */
    public static function every(): ?int
    {
        $every = config('keyring.sessions.sweep_every');

        if (! is_string($every) && ! is_int($every)) {
            return null;
        }

        try {
            $seconds = Duration::seconds($every);
        } catch (Throwable) {
            return null;
        }

        return $seconds > 0 ? max(1, intdiv($seconds, 60)) : null;
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
        return match (true) {
            $minutes < 60 => "*/{$minutes} * * * *",
            $minutes < 1440 => '0 */'.intdiv($minutes, 60).' * * *',
            default => '0 0 * * *',
        };
    }

    /**
     * The most one run ends, and the most it announces again.
     */
    public static function limit(): int
    {
        $limit = config('keyring.sessions.sweep_limit');

        return is_int($limit) && $limit > 0 ? $limit : self::LIMIT;
    }
}
