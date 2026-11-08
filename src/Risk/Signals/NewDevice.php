<?php

namespace Keyring\Risk\Signals;

use Keyring\Contracts\Signal;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;

class NewDevice implements Signal
{
    public function __construct(
        protected int $score = 15,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        return $assessment->attempt?->isNewDevice()
            ? new Finding('new_device', $this->score, 'Signing in from a new device.')
            : null;
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}
