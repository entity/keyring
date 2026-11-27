<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Models\Authenticator;
use Keyring\Sso\Identity;

/**
 * An identity provider's account was accepted as the user's link: for a
 * sign in or a confirm once the account it vouched for matched the link,
 * and for a link once it was added or brought up to date. It carries
 * everything the provider said, such as how the user signed in there
 * (identity->amr and identity->acr), which Keyring counts toward nothing.
 *
 * It fires as the provider's proof is accepted, before the rest of the
 * pipeline: a sign in may still ask for a second factor, or be refused by
 * a risk lock or the account's limits. Authenticated or Confirmed says the
 * whole attempt is done. An account nobody linked fires nothing.
 *
 * The identity's request holds the state, nonce and PKCE code verifier of
 * a request that's spent. A listener in the request sees them, and a
 * queued one gets the request without them, and the claims without the
 * ID token's nonce, at_hash and c_hash (Identity::withoutSecrets()).
 */
class ProviderIdentityAccepted
{
    use Dispatchable, SerializesModels {
        SerializesModels::__serialize as protected serializeModels;
    }

    /**
     * @param  'login'|'confirm'|'link'  $purpose  what it was accepted for, as SingleSignOn::LOGIN, CONFIRM or LINK
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly Authenticator $authenticator,
        #[\SensitiveParameter] public readonly Identity $identity,
        public readonly string $purpose,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        return [
            ...$this->serializeModels(),
            'identity' => $this->identity->withoutSecrets(),
        ];
    }
}
