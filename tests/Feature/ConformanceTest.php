<?php

namespace Keyring\Tests\Feature;

use Illuminate\Support\Facades\Notification;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Testing\KeyringConformance;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;

/**
 * Keyring runs its own conformance suite against a full setup.
 */
class ConformanceTest extends TestCase
{
    use KeyringConformance;

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys(), Totp::class, EmailCode::class, RecoveryCodes::class]);
    }

    protected function keyringUser(): User
    {
        return User::create(['name' => 'Taylor', 'email' => 'taylor-'.uniqid().'@example.com', 'password' => 'password']);
    }
}
