<?php

namespace Keyring\Factors;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Keyring\Contracts\Factor as FactorContract;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * Sensible defaults for factors. Most factors only need key(), categories()
 * and verify().
 */
abstract class Factor implements FactorContract
{
    public function phishingResistant(Authenticator $authenticator): bool
    {
        return false;
    }

    public function priority(): int
    {
        return 50;
    }

    public function authenticators(Authenticatable&Model $user, Collection $stored): Collection
    {
        return $stored->where('factor', $this->key())->values();
    }

    public function challenge(Attempt $attempt, Authenticator $authenticator): array
    {
        return [];
    }

    public function rules(): array
    {
        return ['code' => ['required', 'string', 'max:64']];
    }

    public function limits(Request $request, ?Attempt $attempt): array
    {
        $account = $attempt !== null
            ? $attempt->userId
            : Str::lower((string) $request->input(config('keyring.username')));

        return [
            Limit::perMinute(config('keyring.limits.per_account'))->by($this->key().'|account|'.$account),
            Limit::perMinute(config('keyring.limits.per_ip'))->by($this->key().'|ip|'.$request->ip()),
        ];
    }

    public function errorKey(): string
    {
        return 'code';
    }

    public function present(Authenticator $authenticator): array
    {
        return [
            'factor' => $this->key(),
            'id' => $authenticator->isVirtual() ? null : $authenticator->id,
            'name' => $authenticator->name,
        ];
    }

    /**
     * Record a successful verification of the given authenticator.
     */
    protected function verified(Authenticator $authenticator, ?array $categories = null, ?bool $phishingResistant = null): Verification
    {
        return new Verification(
            factor: $this->key(),
            authenticator: $authenticator->isVirtual() ? null : $authenticator->id,
            categories: $categories ?? $this->categories($authenticator),
            phishingResistant: $phishingResistant ?? $this->phishingResistant($authenticator),
            at: now()->getTimestamp(),
        );
    }

    /**
     * A new, unsaved authenticator of the configured model.
     *
     * @param  array<string, mixed>  $attributes
     */
    protected function makeAuthenticator(array $attributes): Authenticator
    {
        $model = Keyring::authenticatorModel();

        return new $model(['factor' => $this->key(), ...$attributes]);
    }

    /**
     * Whether a user may have more than one of these.
     */
    public function multiple(): bool
    {
        return true;
    }

    /**
     * Strip spaces and dashes users paste in with codes.
     */
    protected function normalizeCode(string $code): string
    {
        return preg_replace('/[\s-]+/', '', $code);
    }
}
