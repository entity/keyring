<?php

namespace Keyring\Testing;

use Illuminate\Support\Timebox;

/**
 * A timebox that never waits, so tests stay fast.
 */
class InstantTimebox extends Timebox
{
    protected function usleep(int $microseconds)
    {
        //
    }
}
