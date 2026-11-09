<?php

namespace Keyring\Testing;

use PHPUnit\Framework\Assert;

/**
 * Decides factor checks in tests without real codes or signatures, so app
 * tests exercise the app's rules, not the WebAuthn spec:
 *
 *     Keyring::fake()->pass('totp', 'passkey')->fail('email-code');
 *
 * Identifying the user (like looking up the email) still runs for real.
 */
class KeyringFake
{
    /** @var array<string, bool> */
    protected array $decisions = [];

    /** @var list<array{factor: string, verified: bool}> */
    protected array $checks = [];

    public function pass(string ...$factors): static
    {
        $this->decisions = array_fill_keys($factors, true) + $this->decisions;

        return $this;
    }

    public function fail(string ...$factors): static
    {
        $this->decisions = array_fill_keys($factors, false) + $this->decisions;

        return $this;
    }

    /**
     * True to pass, false to fail, null to check for real.
     */
    public function decision(string $factor): ?bool
    {
        return $this->decisions[$factor] ?? null;
    }

    /**
     * Note a factor check and how it went, faked or real.
     */
    public function record(string $factor, bool $verified): void
    {
        $this->checks[] = ['factor' => $factor, 'verified' => $verified];
    }

    /**
     * Assert the factor was checked and verified, a number of times if given.
     */
    public function assertVerified(string $factor, ?int $times = null): static
    {
        return $this->assertChecked($factor, true, $times);
    }

    /**
     * Assert the factor was checked and failed, a number of times if given.
     */
    public function assertFailed(string $factor, ?int $times = null): static
    {
        return $this->assertChecked($factor, false, $times);
    }

    public function assertNotChecked(string $factor): static
    {
        Assert::assertSame(0, $this->count($factor), "The [{$factor}] factor was checked.");

        return $this;
    }

    public function assertNothingChecked(): static
    {
        Assert::assertSame([], array_values(array_unique(array_column($this->checks, 'factor'))), 'Factors were checked.');

        return $this;
    }

    protected function assertChecked(string $factor, bool $verified, ?int $times): static
    {
        $count = $this->count($factor, $verified);
        $outcome = $verified ? 'verified' : 'failed';

        $times === null
            ? Assert::assertGreaterThan(0, $count, "The [{$factor}] factor never {$outcome}.")
            : Assert::assertSame($times, $count, "The [{$factor}] factor {$outcome} {$count} times instead of {$times}.");

        return $this;
    }

    protected function count(string $factor, ?bool $verified = null): int
    {
        return count(array_filter($this->checks, fn (array $check) => $check['factor'] === $factor && ($verified === null || $check['verified'] === $verified)));
    }
}
