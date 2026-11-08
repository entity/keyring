<?php

namespace Keyring\Factors;

use Closure;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Keyring\Contracts\Factor as FactorContract;
use Keyring\Devices\DeviceManager;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Pipeline\ConsecutiveLimit;
use Keyring\Pipeline\SharedLimit;
use Keyring\Support\RowLock;

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
     * The per-IP limit is a SharedLimit, so a success never clears it.
     * Requests that don't name an account (like a usernameless passkey) only
     * get the per-IP limit, so they can't fill one bucket every user shares.
     *
     * A browser the account has signed in from before gets a bucket of its
     * own (OWASP "device cookies"), so someone guessing elsewhere can't lock
     * the owner out.
     */
    public function limits(Request $request, ?Attempt $attempt): array
    {
        $account = $attempt !== null
            ? (string) $attempt->userId
            : $this->normalizeAccount((string) $request->input(Keyring::username()));

        $bucket = $this->key().'|account|'.$account.$this->knownDevice($request, $attempt, $account);

        $consecutive = config('keyring.limits.consecutive');

        return array_values(array_filter([
            $account === '' ? null : Limit::perMinute(config('keyring.limits.per_account'))->by($bucket),
            $account === '' || $consecutive === null ? null : ConsecutiveLimit::of($consecutive, $this->key(), $account),
            SharedLimit::perMinute(config('keyring.limits.per_ip'))->by($this->key().'|ip|'.$request->ip()),
        ]));
    }

    /**
     * "|device|{id}" when the request's device cookie belongs to the account.
     */
    protected function knownDevice(Request $request, ?Attempt $attempt, string $account): string
    {
        $device = $account === '' ? null : app(DeviceManager::class)->forBrowser($request)->first(function (Device $device) use ($attempt, $account) {
            $user = $device->user();

            return $user !== null && $account === ($attempt !== null
                ? (string) $user->getAuthIdentifier()
                : $this->normalizeAccount((string) $user->getAttribute(Keyring::username())));
        });

        return $device === null ? '' : '|device|'.$device->id;
    }

    protected function normalizeAccount(string $account): string
    {
        return static::accountKey($account);
    }

    /**
     * How a typed username names its account in rate limits: transliterated
     * too, so spelling variants of one address share a limit.
     */
    public static function accountKey(string $username): string
    {
        return Str::transliterate(Keyring::normalizeUsername($username));
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
        $model = Keyring::authenticatorModel();

        return new $model(['factor' => $this->key(), ...$attributes]);
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
    protected function normalizeCode(string $code): string
    {
        return preg_replace('/[\s-]+/', '', $code);
    }
}
