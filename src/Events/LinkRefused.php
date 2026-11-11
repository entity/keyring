<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * An emailed link was refused: its token was wrong or no longer works, its
 * signature didn't match or had expired. The user is whose link it was,
 * when the link got far enough to say. The token itself is never part of
 * the event.
 */
class LinkRefused
{
    use Dispatchable, SerializesModels;

    /**
     * @param  string  $link  "email_change_confirm", "email_change_revert" or "password_reset", or for a signed link the name of its route
     * @param  'unknown'|'token'|'ended'|'signature'|'expired'  $reason  there's no such change; the token was wrong, or right for a change that's over; the signature was wrong, or right and out of date
     */
    public function __construct(
        public readonly string $link,
        public readonly string $reason,
        public readonly ?Authenticatable $user = null,
    ) {}
}
