<?php

use Keyring\Facades\Keyring;
use Keyring\KeyringManager;

it('registers the manager and merges config', function () {
    expect(Keyring::getFacadeRoot())->toBeInstanceOf(KeyringManager::class)
        ->and(config('keyring.username'))->toBe('email');
});
