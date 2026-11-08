<?php

namespace Keyring\Risk\Signals;

use Keyring\Contracts\Signal;
use Keyring\Models\Device;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;

/**
 * A country none of the user's devices have been seen in. Needs a locator.
 */
class NewCountry implements Signal
{
    public function __construct(
        protected int $score = 30,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $country = $assessment->location()['country'] ?? null;

        if ($country === null) {
            return null;
        }

        $known = Device::query()
            ->whereMorphedTo('authenticatable', $assessment->user)
            ->whereNull('revoked_at')
            ->pluck('location')
            ->map(fn (?array $location) => $location['country'] ?? null)
            ->filter();

        return $known->isNotEmpty() && ! $known->contains($country)
            ? new Finding('new_country', $this->score, "Signing in from a new country ({$country}).")
            : null;
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}
