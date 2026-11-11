<?php

declare(strict_types=1);

namespace Keyring\Concerns;

use Closure;
use Illuminate\Support\Facades\Log;
use Keyring\Pipeline\Steps;

/**
 * The steps a verification runs through, and the app's changes to them.
 */
trait ManagesPipeline
{
    /** @var list<Closure(Steps): (Steps|null)> */
    protected array $pipelineCallbacks = [];

    /**
     * Change the steps a verification goes through.
     *
     * @param  Closure(Steps): (Steps|null)  $callback
     */
    public function pipeline(Closure $callback): static
    {
        $known = $this->customisedSteps()->dangerouslyChanged();

        $this->pipelineCallbacks[] = $callback;

        // Run it now, so a refused change stops the app at boot rather than
        // at the first sign in.
        foreach (array_diff($this->customisedSteps()->dangerouslyChanged(), $known) as $step) {
            Log::warning("Keyring's [{$step}] pipeline step was dangerously removed or replaced, so the security check it performs is off.");
        }

        return $this;
    }

    /**
     * @return list<class-string>
     */
    public function steps(): array
    {
        return $this->customisedSteps()->all();
    }

    /**
     * The steps taken out with dangerouslyReplace() or dangerouslyRemove().
     *
     * @return list<class-string>
     */
    public function dangerouslyChangedSteps(): array
    {
        return $this->customisedSteps()->dangerouslyChanged();
    }

    protected function customisedSteps(): Steps
    {
        $steps = Steps::defaults();

        foreach ($this->pipelineCallbacks as $callback) {
            $steps = $callback($steps) ?? $steps;
        }

        return $steps;
    }
}
