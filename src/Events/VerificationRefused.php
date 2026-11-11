<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Login\Attempt;

/**
 * A sign in or step-up had everything it needed, and was still refused,
 * because steps that have to run for every verification hadn't: the
 * pipeline was rearranged so a request got past them.
 */
class VerificationRefused
{
    use Dispatchable, SerializesModels;

    /**
     * @param  list<class-string>  $skipped  the steps that didn't run
     */
    public function __construct(
        public readonly Attempt $attempt,
        public readonly string $factor,
        public readonly array $skipped,
    ) {}
}
