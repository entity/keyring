<?php

namespace Keyring\Risk;

enum Level: int
{
    case Low = 0;
    case Medium = 1;
    case High = 2;
    case Critical = 3;

    public static function forScore(int $score): self
    {
        return match (true) {
            $score >= config('keyring.risk.levels.critical', 90) => self::Critical,
            $score >= config('keyring.risk.levels.high', 60) => self::High,
            $score >= config('keyring.risk.levels.medium', 30) => self::Medium,
            default => self::Low,
        };
    }
}
