<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Enums\ImpersonationEndReason;

/**
 * An impersonation ended, in the request of the browser it was in: stopped,
 * timed out, or found ended or left with nobody to go back to. $returned
 * says whether the browser is back in the impersonator's own session, or
 * was signed out. $impersonator is null when they've since been deleted,
 * or when the session lost what it had parked. $user is null when the user
 * can no longer be loaded, deleted say. One of the two is always there.
 */
class ImpersonationEnded
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly ?Authenticatable $impersonator,
        public readonly ?Authenticatable $user,
        public readonly ImpersonationEndReason $reason,
        public readonly bool $returned,
    ) {}
}
