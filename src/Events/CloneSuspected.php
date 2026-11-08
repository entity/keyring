<?php

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Keyring\Models\Authenticator;

/**
 * A WebAuthn credential's signature counter went backwards, which happens
 * when a key has been cloned. The response was rejected.
 */
class CloneSuspected
{
    use Dispatchable;

    public function __construct(
        public readonly Authenticator $authenticator,
    ) {}
}
