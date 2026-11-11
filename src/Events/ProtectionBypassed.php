<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Protected attributes were changed with Keyring::withoutProtection(). Worth
 * logging: it's the escape hatch around the email and password flows.
 */
class ProtectionBypassed
{
    use Dispatchable;

    public function __construct(
        public readonly ?string $reason = null,
    ) {}
}
