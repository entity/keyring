<?php

namespace Keyring\Pipeline;

use Illuminate\Cache\RateLimiting\Limit;

/**
 * Failures in a row on one account's factor, however slowly they come (NIST
 * SP 800-63B caps them at 100). Only a success clears them, or for a factor
 * that can start a sign in, a password reset. At the cap the factor is
 * refused for that account. A browser the account has signed in from before
 * keeps a count of its own, so someone guessing elsewhere can't use it up.
 */
class ConsecutiveLimit extends Limit
{
    /** How long a count is kept after its last failure. */
    public const int REMEMBER_FOR = 30 * 86400;

    public static function of(int $maxAttempts, string $factor, string $account, ?string $device = null): self
    {
        return new self(self::keyFor($factor, $account, $device), $maxAttempts, self::REMEMBER_FOR);
    }

    public static function keyFor(string $factor, string $account, ?string $device = null): string
    {
        return $factor.'|consecutive|'.$account.($device === null ? '' : '|device|'.$device);
    }
}
