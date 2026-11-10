<?php

namespace Keyring\Concerns;

use Closure;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Keyring\Support\Input;

/**
 * The guard Keyring signs users in to, and how a typed username finds one
 * of its users.
 */
trait IdentifiesUsers
{
    /** @var (Closure(string): string)|null */
    protected ?Closure $usernameNormalizer = null;

    /** @var (Closure(Request): ((Authenticatable&Model)|null))|null */
    protected ?Closure $userFinder = null;

    public function guard(): StatefulGuard
    {
        return Auth::guard(config('keyring.guard'));
    }

    /**
     * The user signed in to Keyring's guard. Step-up middleware may sit
     * behind an app's own auth middleware, so it never relies on the default.
     *
     * @throws AuthenticationException
     */
    public function user(): Authenticatable&Model
    {
        $user = $this->guard()->user();

        return $user instanceof Model ? $user : throw new AuthenticationException(guards: [config('keyring.guard')]);
    }

    public function provider(?string $guard = null): UserProvider
    {
        $guard ??= config('keyring.guard');

        return Auth::createUserProvider(config("auth.guards.{$guard}.provider"))
            ?? throw new InvalidArgumentException("Keyring's guard [{$guard}] has no user provider. Check the \"guard\" option in config/keyring.php against config/auth.php.");
    }

    /**
     * The session only keeps the user's ID, so anyone the guard's provider
     * wouldn't load back would come back as whoever else has that ID.
     */
    public function belongsToGuard(Authenticatable&Model $user): bool
    {
        $found = $this->provider()->retrieveById($user->getAuthIdentifier());

        return $found instanceof Model && $found->is($user);
    }

    public function username(): string
    {
        return config('keyring.username');
    }

    /**
     * The attribute holding the user's email address, which password resets,
     * email changes and email codes use. The same as the username unless
     * users sign in with something else.
     */
    public function email(): string
    {
        return config('keyring.email');
    }

    /**
     * A typed username as Keyring stores and looks it up: trimmed and
     * lowercased, unless the app says otherwise.
     */
    public function normalizeUsername(string $username): string
    {
        return $this->usernameNormalizer === null
            ? Str::lower(trim($username))
            : ($this->usernameNormalizer)($username);
    }

    /**
     * Normalise usernames your own way, e.g. keep their case, or format phone
     * numbers. Used for lookups, rate limits, email changes and reservations.
     *
     * @param  Closure(string): string  $callback
     */
    public function normalizeUsernamesUsing(Closure $callback): static
    {
        $this->usernameNormalizer = $callback;

        return $this;
    }

    /**
     * Find the user a password sign in is for your own way, e.g. by email or
     * username, or skipping banned accounts. Return null for no account;
     * Keyring checks the password and answers the same either way.
     *
     * @param  Closure(Request): ((Authenticatable&Model)|null)  $callback
     */
    public function findUsersUsing(Closure $callback): static
    {
        $this->userFinder = $callback;

        return $this;
    }

    /**
     * The user a password sign in is for, if any: for a primary factor of
     * your own that should find users the way the password does.
     */
    public function findUser(Request $request): (Authenticatable&Model)|null
    {
        $user = $this->userFinder === null
            ? $this->provider()->retrieveByCredentials([
                $this->username() => $this->normalizeUsername(Input::text($request, $this->username())),
            ])
            : ($this->userFinder)($request);

        return $user instanceof Model ? $user : null;
    }
}
