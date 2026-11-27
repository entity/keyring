<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Models\Authenticator;

/**
 * A sign-in method was kept because removing it would have left the user
 * unable to sign in the way their policy requires ("last_factor"), or
 * because the account's sign-in methods changed too recently ("frozen").
 */
class AuthenticatorRemovalRefused
{
    use Dispatchable, SerializesModels;

    /**
     * @param  'last_factor'|'frozen'  $reason
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly Authenticator $authenticator,
        public readonly string $reason = 'last_factor',
    ) {}
}
