<?php

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;

/**
 * A factor failed to verify. The attempt is null when the user wasn't identified.
 */
class FactorFailed
{
    use Dispatchable;

    public function __construct(
        public readonly ?Attempt $attempt,
        public readonly ?Authenticator $authenticator,
        public readonly string $factor,
        public readonly Request $request,
    ) {}
}
