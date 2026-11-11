<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Models\Authenticator;

/**
 * A WebAuthn credential's signature counter went backwards, which happens
 * when a key has been cloned. The response was rejected.
 */
class CloneSuspected
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticator $authenticator,
    ) {}
}
