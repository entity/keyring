<?php

declare(strict_types=1);

namespace Keyring\Risk\Signals;

use Keyring\Contracts\Signal as SignalContract;
use Keyring\Risk\Checkpoint;

/**
 * Sensible defaults for signals. Most only need assess(), and run while
 * signing in.
 */
abstract class Signal implements SignalContract
{
    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}
