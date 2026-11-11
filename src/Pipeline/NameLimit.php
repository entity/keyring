<?php

namespace Keyring\Pipeline;

use Keyring\Support\Duration;

/**
 * Failures in a row under one username as it was typed, whether or not
 * anyone has it. A name nobody has has no account to count against, so this
 * is kept in the cache, and forgotten "remember_names_for" after the first
 * failure of the run.
 *
 * It's the count the sign-in form answers from. The account's own refuses
 * quietly, so a name with an account, a second name of that account and a
 * name with none are each told "too many attempts" after the same number of
 * their own failures, and by nothing else.
 */
class NameLimit extends AccountLimit
{
    public static function of(int $maxAttempts, string $factor, string $name, bool $known = false): self
    {
        return new self($factor.'|consecutive|'.$name.($known ? '|known' : ''), $maxAttempts, Duration::seconds(config('keyring.limits.remember_names_for')));
    }
}
