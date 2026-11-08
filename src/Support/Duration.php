<?php

namespace Keyring\Support;

use Carbon\CarbonInterface;
use InvalidArgumentException;

final class Duration
{
    /**
     * Parse "90", "30s", "15m", "12h" or "7d" into seconds.
     */
    public static function seconds(string|int $duration): int
    {
        if (is_int($duration) || ctype_digit($duration)) {
            return (int) $duration;
        }

        if (! preg_match('/^(\d+)\s*([smhd])$/i', trim($duration), $matches)) {
            throw new InvalidArgumentException("Invalid duration [{$duration}].");
        }

        return (int) $matches[1] * match (strtolower($matches[2])) {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            default => throw new InvalidArgumentException("Invalid duration [{$duration}]."),
        };
    }

    /**
     * The moment the duration from now ends.
     */
    public static function fromNow(string|int $duration): CarbonInterface
    {
        return now()->addSeconds(self::seconds($duration));
    }

    /**
     * The moment the duration before now began.
     */
    public static function ago(string|int $duration): CarbonInterface
    {
        return now()->subSeconds(self::seconds($duration));
    }
}
