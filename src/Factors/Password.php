<?php

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\PasswordRules;

/**
 * The user's password, kept in the users table so password resets and
 * Laravel's own auth helpers keep working. Users without a password simply
 * don't have this authenticator.
 */
class Password extends Factor implements PrimaryFactor
{
    public function startsLogin(): bool
    {
        return true;
    }

    private static ?string $dummyHash = null;

    public function key(): string
    {
        return 'password';
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Knowledge];
    }

    public function priority(): int
    {
        return 40;
    }

    public function authenticators(Authenticatable&Model $user, Collection $stored): Collection
    {
        return filled($user->getAuthPassword())
            ? new Collection([Authenticator::virtual($this, $user, __('Password'))])
            : new Collection;
    }

    public function rules(): array
    {
        return ['password' => ['required', 'string']];
    }

    public function identificationRules(): array
    {
        return [Keyring::username() => ['required', 'string', 'max:255']];
    }

    public function identify(Request $request): ?Authenticator
    {
        $user = Keyring::findUser($request);

        if ($user === null || blank($user->getAuthPassword())) {
            // Spend the same time hashing as a real check would.
            Hash::check(Str::random(32), self::$dummyHash ??= Hash::make(Str::random(32)));

            return null;
        }

        return Authenticator::virtual($this, $user, __('Password'));
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $user = $authenticator->user();
        $credentials = ['password' => PasswordRules::forVerifying((string) $request->input('password'), $user->getAuthPassword())];

        if (! $this->provider()->validateCredentials($user, $credentials)) {
            return null;
        }

        Keyring::changing(fn () => $this->provider()->rehashPasswordIfRequired($user, $credentials));

        return $this->verified($authenticator);
    }

    public function errorKey(): string
    {
        return 'password';
    }

    protected function provider(): UserProvider
    {
        return Keyring::provider();
    }
}
