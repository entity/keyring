<?php

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Keyring\Enums\Purpose;

/**
 * A factor is about to be verified.
 */
class Attempting
{
    use Dispatchable;

    public function __construct(
        public readonly Request $request,
        public readonly string $factor,
        public readonly Purpose $purpose,
    ) {}
}
