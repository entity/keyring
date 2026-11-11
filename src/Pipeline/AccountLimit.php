<?php

declare(strict_types=1);

namespace Keyring\Pipeline;

use Illuminate\Cache\RateLimiting\Limit;

/**
 * One account's limit on a factor. A sign in that names its account by a
 * typed username has it refuse quietly: the attempt is answered like a wrong
 * proof, without checking it. Saying so would tell whoever asked that the
 * name belongs to an account someone has been guessing at.
 */
class AccountLimit extends Limit
{
    public bool $quiet = false;

    /** How many lockouts in a day it takes for the next lock to hold until the limits are cleared. */
    public ?int $holdAfter = null;

    public function quietly(bool $quiet = true): static
    {
        $this->quiet = $quiet;

        return $this;
    }

    public function holdAfter(?int $lockouts): static
    {
        $this->holdAfter = $lockouts;

        return $this;
    }
}
