<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Risk\Action;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Risk;

/**
 * Risk was assessed and found worth acting on.
 */
class RiskAssessed
{
    use Dispatchable, SerializesModels;

    public function __construct(
        public readonly Authenticatable $user,
        public readonly Risk $risk,
        public readonly Action $action,
        public readonly Checkpoint $checkpoint,
    ) {}
}
