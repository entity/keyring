<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Foundation\Events\Dispatchable;

/**
 * Every user's sessions ended at once (keyring:sign-out --all, or the
 * registry's revokeEveryone()): each session that signed in up to $at, a
 * Unix timestamp. There's no RegisteredSessionEnded for each of them, as
 * the registry can't list them all.
 *
 * $at is a cut-off on when sessions signed in, not "now": one whose first
 * dispatch was lost is sent again by keyring:sweep, up to a day later.
 */
class EveryoneSignedOut
{
    use Dispatchable;

    public function __construct(
        public readonly int $at,
    ) {}
}
