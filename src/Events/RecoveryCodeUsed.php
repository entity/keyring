<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Models\Authenticator;

/**
 * A recovery code was used. Worth telling the user how many they have left.
 */
class RecoveryCodeUsed
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticator $authenticator,
        public readonly int $remaining,
    ) {}
}
