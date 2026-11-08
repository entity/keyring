<?php

namespace Keyring\Pipeline;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\RateLimiter;
use Keyring\Facades\Keyring;
use Keyring\Factors\Factor;
use Keyring\Pipeline\Steps\EnsureNotThrottled;

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

    /**
     * Clear every factor's count for the user, after they recovered the
     * account. Counts start under the typed username (before the user is
     * known) and continue under their ID.
     */
    public static function forget(Authenticatable&Model $user): void
    {
        $accounts = [
            (string) $user->getAuthIdentifier(),
            Factor::accountKey((string) $user->getAttribute(Keyring::username())),
        ];

        foreach (Keyring::registered()->keys() as $factor) {
            foreach ($accounts as $account) {
                RateLimiter::clear(EnsureNotThrottled::key(new Limit(self::keyFor($factor, $account))));
            }
        }
    }
}
