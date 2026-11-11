<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;

/**
 * The challenge page was shown for an authenticator.
 */
class FactorChallenged
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Attempt $attempt,
        public readonly Authenticator $authenticator,
    ) {}
}
