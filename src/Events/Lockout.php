<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;

/**
 * Too many attempts were made for a factor.
 */
class Lockout
{
    use Dispatchable;

    public function __construct(
        public readonly Request $request,
        public readonly string $factor,
        public readonly int $retryAfter,
    ) {}
}
