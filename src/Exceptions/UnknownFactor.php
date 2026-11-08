<?php

namespace Keyring\Exceptions;

use InvalidArgumentException;

class UnknownFactor extends InvalidArgumentException
{
    public static function named(string $key): self
    {
        return new self("Factor [{$key}] is not registered with Keyring.");
    }
}
