<?php

namespace Keyring\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Keyring\Factors\RecoveryCodes;
use Keyring\Models\Authenticator;
use PragmaRX\Google2FA\Google2FA;

/**
 * @extends Factory<Authenticator>
 */
class AuthenticatorFactory extends Factory
{
    protected $model = Authenticator::class;

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

    public function default(): static
    {
        return $this->state(['is_default' => true]);
    }

    public function unconfirmed(): static
    {
        return $this->state(['confirmed_at' => null]);
    }
}
