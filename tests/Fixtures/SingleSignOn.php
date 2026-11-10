<?php

namespace Keyring\Tests\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Factors\Factor;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;

/**
 * A sign in someone else vouches for, like a social login, written the way
 * the recipes suggest. The test says who the provider vouched for.
 */
class SingleSignOn extends Factor implements PrimaryFactor
{
    public static ?string $vouchedFor = null;

    public function key(): string
    {
        return 'sso';
    }

    public function startsLogin(): bool
    {
        return true;
    }

    public function answersChallenges(): bool
    {
        return false;
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Knowledge];
    }

    public function authenticators(Authenticatable&Model $user, Collection $stored): Collection
    {
        return new Collection([Authenticator::virtual($this, $user, 'Single sign-on')]);
    }

    public function identify(Request $request): ?Authenticator
    {
        $user = static::$vouchedFor === null ? null : User::query()->where('email', static::$vouchedFor)->first();

        return $user === null ? null : Authenticator::virtual($this, $user, 'Single sign-on');
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        return $this->verified($authenticator);
    }

    public function identificationRules(): array
    {
        return [];
    }

    public function rules(): array
    {
        return [];
    }

    public function errorKey(): string
    {
        return 'email';
    }
}
