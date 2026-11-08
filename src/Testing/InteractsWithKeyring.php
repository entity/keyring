<?php

namespace Keyring\Testing;

use DateTimeInterface;
use Illuminate\Support\Timebox;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Login\Verification;

/**
 * Test helpers for apps using Keyring.
 *
 *     $this->actingAs($user)->withAssurance(Assurance::AAL2)->get('/billing');
 *     $this->actingAs($user)->freshAt(now()->subHour())->delete('/account');
 */
trait InteractsWithKeyring
{
    protected Assurance $keyringAssurance = Assurance::AAL1;

    protected ?DateTimeInterface $keyringVerifiedAt = null;

    /**
     * Laravel calls this for every test using the trait. Failed checks are
     * slowed down to hide timing in production; tests shouldn't wait.
     */
    protected function setUpInteractsWithKeyring(): void
    {
        $this->app->bind(Timebox::class, InstantTimebox::class);
    }

    /**
     * Pretend the signed-in user reached this assurance level.
     */
    public function withAssurance(Assurance $level): static
    {
        $this->keyringAssurance = $level;

        return $this->withKeyringSession();
    }

    /**
     * Pretend the signed-in user last verified a factor at this time.
     */
    public function freshAt(DateTimeInterface $at): static
    {
        $this->keyringVerifiedAt = $at;

        return $this->withKeyringSession();
    }

    protected function withKeyringSession(): static
    {
        $at = ($this->keyringVerifiedAt ?? now())->getTimestamp();

        $verifications = match ($this->keyringAssurance) {
            Assurance::None => [],
            Assurance::AAL1 => [new Verification('password', null, [Category::Knowledge], at: $at)],
            Assurance::AAL2 => [
                new Verification('password', null, [Category::Knowledge], at: $at),
                new Verification('totp', 'testing', [Category::Possession], at: $at),
            ],
            Assurance::AAL3 => [new Verification('passkey', 'testing', [Category::Possession, Category::Inherence], phishingResistant: true, at: $at)],
        };

        return $this->withSession([
            'keyring.verified' => collect($verifications)
                ->mapWithKeys(fn (Verification $verification) => [$verification->authenticator ?? $verification->factor => $verification->toArray()])
                ->all(),
        ]);
    }
}
