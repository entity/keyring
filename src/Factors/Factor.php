<?php

namespace Keyring\Factors;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Keyring\Contracts\Factor as FactorContract;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\RowLock;
use Keyring\Support\Throttle;

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

    public function deviceBound(Authenticator $authenticator): bool
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

    /**
     * Per IP address, per account, and failures in a row. Override to give
     * a factor limits of its own.
     */
    public function limits(Request $request, ?Attempt $attempt): array
    {
        return app(Throttle::class)->limitsFor($this, $request, $attempt);
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
     *
     * @param  list<Category>|null  $categories
     */
    protected function verified(Authenticator $authenticator, ?array $categories = null, ?bool $phishingResistant = null, ?bool $deviceBound = null): Verification
    {
        return Verification::of($authenticator, $categories, $phishingResistant, $deviceBound);
    }

    /**
     * Use up something single-use on the authenticator (a TOTP step, a
     * recovery code). The callback gets a fresh, row-locked copy and returns
     * whether it may be used, so two requests with the same code can't both
     * pass. Changes it makes are saved.
     *
     * @param  Closure(Authenticator): bool  $use
     */
    protected function consume(Authenticator $authenticator, Closure $use): bool
    {
        return RowLock::hold($authenticator, function (?Authenticator $locked) use ($authenticator, $use) {
            if ($locked === null || ! $use($locked)) {
                return false;
            }

            $locked->save();
            $authenticator->setRawAttributes($locked->getAttributes(), sync: true);

            return true;
        });
    }

    /**
     * A new, unsaved authenticator of the configured model.
     *
     * @param  array<string, mixed>  $attributes
     */
    protected function makeAuthenticator(array $attributes): Authenticator
    {
        return Keyring::authenticatorModel()::make(['factor' => $this->key(), ...$attributes]);
    }

    /**
     * Rules for confirming an enrollment: the factor's own, plus an optional
     * name for the new authenticator.
     *
     * @return array<string, mixed>
     */
    public function enrollmentRules(): array
    {
        return [...$this->rules(), 'name' => ['nullable', 'string', 'max:64']];
    }

    /**
     * The name the user gave a new authenticator, or the default.
     */
    protected function nameFrom(Request $request, string $default): string
    {
        return $request->string('name')->trim()->limit(64, '')->value() ?: $default;
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
    protected function normalizeCode(#[\SensitiveParameter] string $code): string
    {
        return preg_replace('/[\s-]+/', '', $code);
    }
}
