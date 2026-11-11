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

    /** Keyring's own tests run on Laravel's default hasher. */
    private bool $acknowledgesBcrypt = true;

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

    /**
     * @return list<class-string>
     */
    protected function keyringAcknowledgedDangerousSteps(): array
    {
        return $this->acknowledged;
    }

    protected function keyringAcknowledgesBcryptLimit(): bool
    {
        return $this->acknowledgesBcrypt;
    }

    public function test_the_suite_fails_while_bcrypt_limits_passwords_to_72_bytes(): void
    {
        $this->acknowledgesBcrypt = false;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('Set HASH_DRIVER=argon2id');

        $this->test_keyring_takes_passwords_of_64_characters();
    }

    public function test_the_suite_passes_with_a_hasher_that_reads_a_whole_password(): void
    {
        $this->acknowledgesBcrypt = false;
        config(['hashing.driver' => 'argon2id']);

        $this->test_keyring_takes_passwords_of_64_characters();
    }

    public function test_the_suite_fails_when_the_longest_password_allowed_is_under_64_characters(): void
    {
        config(['keyring.passwords.max' => 63]);

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage('keyring.passwords.max');

        $this->test_keyring_takes_passwords_of_64_characters();
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
