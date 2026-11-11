<?php

declare(strict_types=1);

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
        $here = $this->coordinates($assessment->location());

        if ($here === null) {
            return null;
        }

        $last = Keyring::deviceModel()::query()
            ->ownedBy($assessment->user)
            ->whereNotNull('location->latitude')
            ->whereNotNull('location->longitude')
            ->latest('last_seen_at')
            ->first();

        $there = $this->coordinates($last?->location);

        if ($last?->last_seen_at === null || $there === null) {
            return null;
        }

        $km = $this->distance(...$there, ...$here);
        $hours = max(1 / 60, $last->last_seen_at->diffInSeconds(now()) / 3600);

        return $km >= $this->minKm && $km / $hours > $this->maxKph
            ? new Finding('impossible_travel', $this->score, sprintf('%d km from the last sign in, %d minutes later.', $km, $hours * 60))
            : null;
    }

    /**
     * A location's latitude and longitude, when it has both as numbers. A
     * locator may hand them over as it read them, as text.
     *
     * @param  array<string, mixed>|null  $location
     * @return array{float, float}|null
     */
    protected function coordinates(?array $location): ?array
    {
        $latitude = $location['latitude'] ?? null;
        $longitude = $location['longitude'] ?? null;

        return is_numeric($latitude) && is_numeric($longitude) ? [(float) $latitude, (float) $longitude] : null;
    }

    protected function distance(float $lat1, float $lon1, float $lat2, float $lon2): float
    {
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);
        $a = sin($dLat / 2) ** 2 + cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon / 2) ** 2;

        return 6371 * 2 * atan2(sqrt($a), sqrt(1 - $a));
    }
}
