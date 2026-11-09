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
            $score >= config('keyring.risk.levels.critical') => self::Critical,
            $score >= config('keyring.risk.levels.high') => self::High,
            $score >= config('keyring.risk.levels.medium') => self::Medium,
            default => self::Low,
        };
    }
}
