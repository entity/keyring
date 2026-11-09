<?php

namespace Keyring\Pipeline;

use Illuminate\Cache\RateLimiting\Limit;

/**
 * Failures in a row on one account's factor, however slowly they come (NIST
 * SP 800-63B caps them at 100). Only a success, or a password reset, clears
 * them. At the cap the factor is refused for that account.
 */
class ConsecutiveLimit extends Limit
{
    /** How long a count is kept after its last failure. */
    public const int REMEMBER_FOR = 30 * 86400;

    public static function of(int $maxAttempts, string $factor, string $account): self
    {
        return new self(self::keyFor($factor, $account), $maxAttempts, self::REMEMBER_FOR);
    }

    public static function keyFor(string $factor, string $account): string
    {
        return $factor.'|consecutive|'.$account;
    }
}
