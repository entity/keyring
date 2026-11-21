<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;

/**
 * The challenge page was shown for an authenticator.
 */
class FactorChallenged
{
    use Dispatchable, SerializesModels {
        SerializesModels::__serialize as protected serializeModels;
    }

    public function __construct(
        public readonly Attempt $attempt,
        public readonly Authenticator $authenticator,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        if ($this->authenticator->exists) {
            return $this->serializeModels();
        }

        // An unsaved authenticator, such as the password's, couldn't be
        // found again by its ID. It's kept as it is instead, without its
        // secret or the user loaded with it.
        return [...$this->serializeModels(), 'authenticator' => $this->authenticator->forQueue()];
    }
}
