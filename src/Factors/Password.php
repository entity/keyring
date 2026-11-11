<?php

declare(strict_types=1);

namespace Keyring\Factors;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Support\Input;
use Keyring\Support\PasswordRules;
use Keyring\Support\RowLock;

/**
 * The user's password, kept in the users table so password resets and
 * Laravel's own auth helpers keep working. Users without a password simply
 * don't have this authenticator.
 */
class Password extends Factor implements PrimaryFactor
{
    public const string KEY = 'password';

    public function key(): string
    {
        return self::KEY;
    }

    public function startsLogin(): bool
    {
        return true;
    }

    public function answersChallenges(): bool
    {
        return true;
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
            $this->stall();

            return null;
        }

        return Authenticator::virtual($this, $user, __('Password'));
    }

    /**
     * One hash, as checking a password costs, made on every request.
     * Keeping a hash to check against would only save its cost where the
     * process outlives the request, and show which those are.
     */
    public function stall(): void
    {
        Hash::make(Str::random(32));
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        $user = $authenticator->user();
        $credentials = ['password' => PasswordRules::forVerifying((string) Input::get($request, 'password'), $user->getAuthPassword())];

        if (! $this->provider()->validateCredentials($user, $credentials)) {
            return null;
        }

        if (Hash::needsRehash((string) $user->getAuthPassword()) && ! $this->rehash($user, $credentials)) {
            return null;
        }

        return $this->verified($authenticator);
    }

    /**
     * Save the password under the app's current hashing, but only over the
     * hash it was just checked against. A reset or change that finished
     * since this request loaded the user has stored a new password, and a
     * rehash of the old one would put it back: then it fails, as the old
     * password now should.
     *
     * @param  array{password: string}  $credentials
     */
    protected function rehash(Authenticatable&Model $user, #[\SensitiveParameter] array $credentials): bool
    {
        return RowLock::hold($user, function (?Model $stored) use ($user, $credentials) {
            if (! $stored instanceof Authenticatable || ! hash_equals((string) $user->getAuthPassword(), (string) $stored->getAuthPassword())) {
                return false;
            }

            app(ProtectedAttributes::class)->changing(fn () => $this->provider()->rehashPasswordIfRequired($user, $credentials));

            return true;
        });
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
