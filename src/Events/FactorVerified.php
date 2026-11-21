<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Arr;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * A factor's proof was right, at sign in or step-up. When the policy asks
 * for more than one, each fires this: Authenticated or Confirmed says the
 * whole attempt is done.
 */
class FactorVerified
{
    use Dispatchable, SerializesModels {
        SerializesModels::__serialize as protected serializeModels;
    }

    public function __construct(
        public readonly Attempt $attempt,
        public readonly Authenticator $authenticator,
        public readonly Verification $verification,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        if ($this->authenticator->exists) {
            return $this->serializeModels();
        }

        // A password has no stored authenticator, so queued by its ID it
        // couldn't be found again. It's kept as it is instead, without the
        // user loaded with it or a secret.
        $authenticator = $this->authenticator->newInstance()
            ->setRawAttributes(Arr::except($this->authenticator->getAttributes(), ['secret']), sync: true);

        return [...$this->serializeModels(), 'authenticator' => $authenticator];
    }
}
