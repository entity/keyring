<?php

namespace Keyring\Support;

use Illuminate\Cache\RateLimiter;
use Illuminate\Validation\ValidationException;

final class Throttle
{
    /**
     * Laravel's "too many attempts" message on the field, as a 429.
     */
    public static function exception(string $field, int $seconds): ValidationException
    {
        return ValidationException::withMessages([
            $field => __('auth.throttle', ['seconds' => $seconds, 'minutes' => (int) ceil($seconds / 60)]),
        ])->status(429);
    }

    /**
     * Count a code about to be sent, and refuse it when the account has been
     * sent its limit for the factor (three every ten minutes, unless the
     * limits.codes options say otherwise). Counted per account,
     * not per sign in, so starting again doesn't buy more, and sign ins,
     * step-ups and enrollments share the count.
     */
    public static function sending(string $factor, int|string $userId): void
    {
        $limiter = app(RateLimiter::class);
        $key = 'keyring-send:'.$factor.'|'.$userId;

        if ($limiter->tooManyAttempts($key, config('keyring.limits.codes'))) {
            throw self::exception('code', $limiter->availableIn($key));
        }

        $limiter->hit($key, Duration::seconds(config('keyring.limits.codes_per')));
    }
}
