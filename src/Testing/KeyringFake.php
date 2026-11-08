<?php

namespace Keyring\Testing;

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

    public function pass(string ...$factors): static
    {
        foreach ($factors as $factor) {
            $this->decisions[$factor] = true;
        }

        return $this;
    }

    public function fail(string ...$factors): static
    {
        foreach ($factors as $factor) {
            $this->decisions[$factor] = false;
        }

        return $this;
    }

    /**
     * True to pass, false to fail, null to check for real.
     */
    public function decision(string $factor): ?bool
    {
        return $this->decisions[$factor] ?? null;
    }
}
