<?php

namespace Keyring\Risk\Signals;

use Keyring\Features;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;

class NewDevice extends Signal
{
    public function __construct(
        protected int $score = 15,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        // Without devices, every browser looks new.
        return Features::enabled(Features::devices()) && $assessment->attempt?->isNewDevice()
            ? new Finding('new_device', $this->score, 'Signing in from a new device.')
            : null;
    }
}
