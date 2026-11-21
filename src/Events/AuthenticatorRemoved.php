<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Models\Authenticator;

/**
 * The user removed an authenticator. Worth telling them by email.
 *
 * Queued, the user goes by their ID as in every other event. The
 * authenticator is already deleted, so a queued listener couldn't fetch it
 * again: it's kept as it was, without its secret, its earlier values or
 * anything loaded with it.
 */
class AuthenticatorRemoved
{
    use Dispatchable, SerializesModels {
        SerializesModels::__serialize as protected serializeModels;
    }

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Authenticator $authenticator,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        return [...$this->serializeModels(), 'authenticator' => $this->authenticator->forQueue()];
    }
}
