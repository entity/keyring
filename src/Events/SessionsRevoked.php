<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * Sessions were signed out: "sign out everywhere else", one ended from the
 * sessions list, an administrator's keyring:sign-out, or an account the app
 * stopped letting sign in.
 */
class SessionsRevoked
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly int $count,
    ) {}
}
