<?php

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Models\Authenticator;

/**
 * A recovery code was used. Worth telling the user how many they have left.
 */
class RecoveryCodeUsed
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticator $authenticator,
        public readonly int $remaining,
    ) {}
}
