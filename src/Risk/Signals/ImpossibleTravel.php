<?php

namespace Keyring\Risk\Signals;

use Keyring\Facades\Keyring;
use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;

/**
 * Two sign ins further apart than anyone could travel in the time between.
 * Needs a locator that gives coordinates.
 */
class ImpossibleTravel extends Signal
{
    public function __construct(
        protected int $score = 60,
        protected int $maxKph = 900,
        protected int $minKm = 500,
    ) {}

    public function assess(Assessment $assessment): ?Finding
    {
        $here = $assessment->location();

        if (! isset($here['latitude'], $here['longitude'])) {
            return null;
        }

        $last = Keyring::deviceModel()::query()
            ->ownedBy($assessment->user)
            ->whereNotNull('location->latitude')
            ->whereNotNull('location->longitude')
            ->latest('last_seen_at')
            ->first();

        $there = $last?->location;

        if ($last?->last_seen_at === null || ! isset($there['latitude'], $there['longitude'])) {
            return null;
        }

        $km = $this->distance($there['latitude'], $there['longitude'], $here['latitude'], $here['longitude']);
        $hours = max(1 / 60, $last->last_seen_at->diffInSeconds(now()) / 3600);

        return $km >= $this->minKm && $km / $hours > $this->maxKph
            ? new Finding('impossible_travel', $this->score, sprintf('%d km from the last sign in, %d minutes later.', $km, $hours * 60))
            : null;
    }

    protected function distance(float $lat1, float $lon1, float $lat2, float $lon2): float
    {
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);
        $a = sin($dLat / 2) ** 2 + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) ** 2;

        return 6371 * 2 * atan2(sqrt($a), sqrt(1 - $a));
    }
}
