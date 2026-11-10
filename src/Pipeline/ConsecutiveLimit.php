<?php

namespace Keyring\Pipeline;

use Illuminate\Cache\RateLimiting\Limit;
use Keyring\Support\Duration;

/**
 * Failures in a row on one account's factor, however slowly they come, 100
 * by default. Only a success clears them, or for a factor that can start a
 * sign in, a password reset. At the cap the factor is
 * refused for that account. A browser the account has signed in from before
 * keeps a count of its own, so someone guessing elsewhere can't use it up.
 */
class ConsecutiveLimit extends Limit
{
    public static function of(int $maxAttempts, string $factor, string $account, ?string $device = null): self
    {
        return new self(self::keyFor($factor, $account, $device), $maxAttempts, Duration::seconds(config('keyring.limits.remember_failures_for')));
    }

    public static function keyFor(string $factor, string $account, ?string $device = null): string
    {
        return $factor.'|consecutive|'.$account.($device === null ? '' : '|device|'.$device);
    }
}
