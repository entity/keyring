<?php

namespace Keyring\Pipeline;

use Illuminate\Cache\RateLimiting\Limit;

/**
 * A limit shared by every account, like the one per IP address. A success
 * only takes back its own attempt, so one account signing in can't reset
 * the limit for the others. Reaching it refuses attempts until its window
 * ends and never locks, so one person can't lock a whole address out.
 */
class SharedLimit extends Limit
{
    //
}
