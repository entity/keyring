<?php

declare(strict_types=1);

namespace Keyring\Pipeline;

use Illuminate\Cache\RateLimiting\Limit;

/**
 * A limit shared by every account, like the one per IP address. A success
 * only takes back its own attempt, so one account signing in can't reset
 * the limit for the others. Its locks stay short, so one person can't keep
 * a whole address out for long.
 */
class SharedLimit extends Limit
{
    //
}
