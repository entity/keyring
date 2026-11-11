<?php

declare(strict_types=1);

namespace Keyring\Support;

use Closure;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Timebox;

/**
 * Holds a refusal for keyring.timebox, so how long it took doesn't say why
 * it was refused: whether the account exists, whether a reset link is
 * outstanding, whether a limit had already settled the answer.
 *
 * The wait only hides what's shorter than it. Work that ran past it isn't
 * padded at all, and the slowest thing a refusal does, hashing a password,
 * costs what the server's hashing settings make it cost. So a refusal that
 * took longer than the timebox is reported, once an hour: that is where the
 * real cost on the real hardware shows.
 */
final class Refusal
{
    /**
     * Run the work on a timebox of its own. It returns its result and
     * whether it went through: only then is the wait skipped.
     *
     * @template TResult
     *
     * @param  Closure(): array{TResult, bool}  $work
     * @return TResult
     */
    public static function timed(Closure $work): mixed
    {
        $box = Duration::milliseconds(config('keyring.timebox')) * 1000;
        $started = hrtime(true);

        return app(Timebox::class)->call(function (Timebox $timebox) use ($work, $box, $started) {
            [$result, $wentThrough] = $work();

            if ($wentThrough) {
                $timebox->returnEarly();
            } elseif (($took = intdiv(hrtime(true) - $started, 1000)) > $box) {
                self::outran($took, $box);
            }

            return $result;
        }, $box);
    }

    private static function outran(int $took, int $box): void
    {
        rescue(fn () => RateLimiter::attempt('keyring:timebox-outrun', 1, fn () => Log::warning(sprintf(
            'Keyring refused a request in %dms, longer than the %dms every refusal is held for (keyring.timebox), so how long a refusal takes may show whether an account exists. '
            .'The timebox has to be longer than one password hash takes on this server: raise keyring.timebox.',
            intdiv($took, 1000),
            intdiv($box, 1000),
        )), 3600), report: false);
    }
}
