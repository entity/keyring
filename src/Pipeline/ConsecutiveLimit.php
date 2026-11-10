<?php

namespace Keyring\Pipeline;

use Keyring\Support\Duration;

/**
 * Failures in a row on one account's factor, however slowly they come, 100
 * by default. Only a success clears them, or for a factor that can start a
 * sign in, a new password. At the cap the factor is refused for that
 * account. Browsers the account has signed in from share a count of their
 * own, so someone guessing elsewhere can't use it up.
 */
class ConsecutiveLimit extends AccountLimit
{
    public static function of(int $maxAttempts, string $factor, string $account, bool $known = false): self
    {
        return new self(self::keyFor($factor, $account, $known), $maxAttempts, Duration::seconds(config('keyring.limits.remember_failures_for')));
    }

    public static function keyFor(string $factor, string $account, bool $known = false): string
    {
        return $factor.'|consecutive|'.$account.($known ? '|known' : '');
    }
}
