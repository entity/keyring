<?php

namespace Keyring\Contracts;

use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;

/**
 * One thing that might make a sign in or session suspicious. Small and
 * focused; findings add up into a risk level.
 */
interface Signal
{
    public function assess(Assessment $assessment): ?Finding;

    /**
     * Where this signal runs. Request signals run on every signed-in
     * request, so they must be cheap.
     *
     * @return list<Checkpoint>
     */
    public function checkpoints(): array;
}
