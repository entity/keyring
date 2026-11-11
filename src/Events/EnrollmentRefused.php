<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * A sign-in method wasn't added: its factor turned the confirmation down
 * (a wrong code, a key it won't take), or the account isn't allowed to add
 * one yet because its email address is unproven.
 */
class EnrollmentRefused
{
    use Dispatchable, SerializesModels;

    /**
     * @param  'invalid'|'not_allowed'  $reason
     */
    public function __construct(
        public readonly Authenticatable $user,
        public readonly string $factor,
        public readonly string $reason,
    ) {}
}
