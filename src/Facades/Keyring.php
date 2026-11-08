<?php

namespace Keyring\Facades;

use Illuminate\Support\Facades\Facade;
use Keyring\KeyringManager;

/**
 * @see KeyringManager
 */
class Keyring extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return KeyringManager::class;
    }
}
