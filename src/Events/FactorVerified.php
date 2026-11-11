<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * A factor was verified successfully.
 */
class FactorVerified
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Attempt $attempt,
        public readonly Authenticator $authenticator,
        public readonly Verification $verification,
    ) {}
}
