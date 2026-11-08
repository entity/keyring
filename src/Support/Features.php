<?php

namespace Keyring\Support;

final class Features
{
    public static function enabled(string $feature): bool
    {
        return (bool) config('keyring.features.'.$feature, false);
    }
}
