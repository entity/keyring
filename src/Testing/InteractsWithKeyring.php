<?php

namespace Keyring\Testing;

use DateTimeInterface;
use Illuminate\Contracts\Support\MessageBag as MessageBagContract;
use Illuminate\Support\MessageBag;
use Illuminate\Support\Timebox;
use Illuminate\Support\ViewErrorBag;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use PragmaRX\Google2FA\Google2FA;

/**
 * Test helpers for apps using Keyring.
 *
 *     $this->actingAs($user)->withAssurance(Assurance::AAL2)->get('/billing');
 *     $this->actingAs($user)->freshAt(now()->subHour())->delete('/account');
 *     $this->actingAs($user)->verifiedWith($passkey)->post('/user/email', [...]);
 */
trait InteractsWithKeyring
{
    protected Assurance $keyringAssurance = Assurance::AAL1;

    protected ?DateTimeInterface $keyringVerifiedAt = null;

    /** @var list<Authenticator> */
    protected array $keyringVerifiedWith = [];

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
        $this->keyringVerifiedWith = [];

        return $this->withKeyringSession();
    }

    /**
     * Pretend the signed-in user verified their password and these
     * authenticators, for code that looks up what a session was verified
     * with. The level is whatever they reach, so this replaces
     * withAssurance().
     */
    public function verifiedWith(Authenticator ...$authenticators): static
    {
        $this->keyringVerifiedWith = array_values($authenticators);

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

    /**
     * The validation errors the last request flashed. Laravel stores them as
     * a plain array once it saves a JSON session (the default in new apps),
     * so session('errors') isn't always a ViewErrorBag.
     */
    public function sessionErrors(string $bag = 'default'): MessageBagContract
    {
        $errors = session('errors');

        if ($errors instanceof ViewErrorBag) {
            return $errors->getBag($bag);
        }

        return new MessageBag(is_array($errors) ? $errors[$bag]['messages'] ?? [] : []);
    }

    /**
     * The code an authenticator app would show right now for a TOTP
     * authenticator, or for a secret.
     */
    public function totpCode(Authenticator|string $authenticator): string
    {
        return app(Google2FA::class)->getCurrentOtp($authenticator instanceof Authenticator ? $authenticator->secret : $authenticator);
    }

    protected function withKeyringSession(): static
    {
        $at = ($this->keyringVerifiedAt ?? now())->getTimestamp();

        $password = new Verification('password', null, [Category::Knowledge], at: $at);

        $verifications = $this->keyringVerifiedWith !== [] ? [
            $password,
            ...array_map(function (Authenticator $authenticator) use ($at) {
                $verification = Verification::of($authenticator);

                return new Verification($verification->factor, $verification->authenticator, $verification->categories, $verification->phishingResistant, $at, $verification->deviceBound);
            }, $this->keyringVerifiedWith),
        ] : match ($this->keyringAssurance) {
            Assurance::None => [],
            Assurance::AAL1 => [$password],
            Assurance::AAL2 => [
                $password,
                new Verification('totp', 'testing', [Category::Possession], at: $at),
            ],
            Assurance::AAL3 => [new Verification('security-key', 'testing', [Category::Possession, Category::Inherence], phishingResistant: true, at: $at, deviceBound: true)],
        };

        return $this->withSession([
            SessionAssurance::KEY => collect($verifications)
                ->mapWithKeys(fn (Verification $verification) => [$verification->authenticator ?? $verification->factor => $verification->toArray()])
                ->all(),
        ]);
    }
}
