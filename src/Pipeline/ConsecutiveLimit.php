<?php

declare(strict_types=1);

namespace Keyring\Pipeline;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Keyring\Models\FailureCount;

/**
 * Failures in a row on one of an account's authenticators, however slowly
 * they come: 100 by default, NIST SP 800-63B-4's cap. They're counted in the
 * database, so clearing the cache doesn't start the count over, and at the
 * cap the authenticator is refused for the account until that's dealt with.
 * Nothing brings it back by itself.
 *
 * Every browser shares the one cap, so there are never more failures in a
 * row than that. Browsers the account hasn't signed in from may only make
 * part of them ("consecutive_elsewhere"), which leaves the rest to the
 * owner's own: someone guessing elsewhere can't use the whole of it up. A
 * success only clears what its own kind of browser failed, or the owner
 * signing in would hand whoever is guessing elsewhere their guesses back.
 */
class ConsecutiveLimit extends AccountLimit
{
    /** Whose authenticator it is. Nobody's when the name typed found no account. */
    public (Authenticatable&Model)|null $user = null;

    public string $factor = '';

    /** The authenticator's ID, or the factor's key for one with no row, like the password. */
    public string $authenticator = '';

    /** Whether the attempt comes from a browser the account has signed in from. */
    public bool $known = false;

    /** How many failures in a row it allows from anywhere. Null for no cap. */
    public ?int $cap = null;

    /** How many of them the attempt's kind of browser may make. */
    public ?int $share = null;

    /** The row as it stood when the attempt was checked, if there was one. */
    public ?FailureCount $count = null;

    /** Whether the attempt was counted before it was verified. */
    public bool $reserved = false;

    /**
     * @param  int|null  $cap  failures in a row from anywhere, null for no cap
     * @param  int|null  $share  how many of them the attempt's kind of browser may make, null for all
     */
    public static function of((Authenticatable&Model)|null $user, string $factor, bool $known, ?int $cap, ?int $share = null): self
    {
        $limit = new self($factor.'|consecutive'.($known ? '|known' : ''), $cap ?? PHP_INT_MAX, 0);

        $limit->user = $user;
        $limit->factor = $factor;
        $limit->authenticator = $factor;
        $limit->known = $known;
        $limit->cap = $cap;
        $limit->share = $cap === null ? null : min($cap, $share ?? $cap);

        return $limit;
    }

    /**
     * How many failures in a row the attempt's kind of browser had made
     * when it was checked.
     */
    public function failures(): int
    {
        return (int) $this->count?->getAttribute($this->column());
    }

    /**
     * The column counting failures from the attempt's kind of browser.
     */
    public function column(): string
    {
        return $this->known ? 'known_failures' : 'failures';
    }

    /**
     * The column saying when the attempt's kind of browser was refused.
     */
    public function lockColumn(): string
    {
        return $this->known ? 'known_locked_at' : 'locked_at';
    }
}
