<?php

namespace Keyring\Tests\Feature;

use Illuminate\Support\Facades\Notification;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Testing\KeyringConformance;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;
use PHPUnit\Framework\AssertionFailedError;

/**
 * Keyring runs its own conformance suite against a full setup.
 */
class ConformanceTest extends TestCase
{
    use KeyringConformance;

    /** @var list<class-string> */
    private array $acknowledged = [];

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys(), Totp::class, EmailCode::asSecondFactor(), RecoveryCodes::class]);
    }

    protected function keyringUser(): User
    {
        return User::create(['name' => 'Taylor', 'email' => 'taylor-'.uniqid().'@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    }

    protected function keyringAcknowledgedDangerousSteps(): array
    {
        return $this->acknowledged;
    }

    public function test_the_suite_fails_when_a_mandatory_step_was_taken_out(): void
    {
        Keyring::pipeline(fn (Steps $steps) => $steps->dangerouslyRemove(EnsureNotThrottled::class));

        $this->expectException(AssertionFailedError::class);

        $this->test_keyring_keeps_its_mandatory_pipeline_steps();
    }

    public function test_the_suite_accepts_a_mandatory_step_taken_out_on_purpose(): void
    {
        Keyring::pipeline(fn (Steps $steps) => $steps->dangerouslyRemove(EnsureNotThrottled::class));
        $this->acknowledged = [EnsureNotThrottled::class];

        $this->test_keyring_keeps_its_mandatory_pipeline_steps();
    }
}
