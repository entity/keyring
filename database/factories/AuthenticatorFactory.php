<?php

namespace Keyring\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Attributes\UseModel;
use Illuminate\Database\Eloquent\Factories\Factory;
use Keyring\Factors\RecoveryCodes;
use Keyring\Models\Authenticator;
use PragmaRX\Google2FA\Google2FA;

/**
 * @extends Factory<Authenticator>
 */
#[UseModel(Authenticator::class)]
class AuthenticatorFactory extends Factory
{
    public function definition(): array
    {
        return [
            'factor' => 'totp',
            'name' => 'Authenticator app',
            'secret' => app(Google2FA::class)->generateSecretKey(),
            'is_default' => false,
            'confirmed_at' => now(),
        ];
    }

    public function totp(?string $secret = null): static
    {
        return $this->state(fn () => [
            'factor' => 'totp',
            'name' => 'Authenticator app',
            'secret' => $secret ?? app(Google2FA::class)->generateSecretKey(),
        ]);
    }

    /**
     * @param  list<string>  $codes
     */
    public function recoveryCodes(array $codes = ['aaaaa-11111', 'bbbbb-22222', 'ccccc-33333']): static
    {
        return $this->state(fn () => [
            'factor' => 'recovery',
            'name' => 'Recovery codes',
            'secret' => app(RecoveryCodes::class)->secretFor($codes),
        ]);
    }

    /**
     * A passkey that only works with Keyring::fake(), or with a
     * VirtualAuthenticator enrolled through the real flow.
     */
    public function passkey(bool $synced = true): static
    {
        return $this->webauthn('passkey', 'Passkey', userVerified: true, synced: $synced);
    }

    public function securityKey(bool $userVerified = false): static
    {
        return $this->webauthn('security-key', 'Security key', $userVerified, synced: false);
    }

    /**
     * A key whose model was checked against a trusted root when it was added.
     */
    public function attested(string $aaguid, string $type = 'basic'): static
    {
        return $this->state(['aaguid' => $aaguid, 'attestation' => $type]);
    }

    public function emailCode(): static
    {
        return $this->state(['factor' => 'email-code', 'name' => 'Email', 'secret' => null]);
    }

    protected function webauthn(string $factor, string $name, bool $userVerified, bool $synced): static
    {
        return $this->state(fn () => [
            'factor' => $factor,
            'name' => $name,
            'secret' => null,
            'credential_id' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
            'public_key' => '{}',
            'transports' => ['usb'],
            'meta' => ['user_verified' => $userVerified, 'backup_eligible' => $synced],
        ]);
    }

    public function default(): static
    {
        return $this->state(['is_default' => true]);
    }

    public function unconfirmed(): static
    {
        return $this->state(['confirmed_at' => null]);
    }
}
