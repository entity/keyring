<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * A rate limiter on Keyring's form routes refused a request: "keyring" on
 * registration, resets, changes and the emailed links, or
 * "keyring-login-options" on passkey options. The sign-in limits have their
 * own event (Lockout).
 */
class RateLimited
{
    use Dispatchable, SerializesModels;

    /**
     * @param  Authenticatable|null  $user  whoever is signed in, if anyone is
     * @param  string|null  $route  the name of the route that was asked for
     * @param  int  $retryAfter  seconds until a request would be let through
     */
    public function __construct(
        public readonly ?Authenticatable $user,
        public readonly string $limiter,
        public readonly ?string $route,
        public readonly int $retryAfter,
    ) {}
}
