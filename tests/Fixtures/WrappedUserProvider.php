<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Auth;

/**
 * A user provider of the app's own that still hands back Eloquent models,
 * as one wrapping Eloquent's (to cache users, say) would. Keyring can't ask
 * it which model it loads.
 */
class WrappedUserProvider implements UserProvider
{
    public function __construct(
        protected EloquentUserProvider $users,
    ) {}

    /**
     * Register it as the "wrapped" driver and use it for the users provider.
     */
    public static function use(): void
    {
        Auth::provider('wrapped', fn ($app, array $config) => new self(new EloquentUserProvider($app['hash'], $config['model'])));

        config(['auth.providers.users.driver' => 'wrapped']);
    }

    public function retrieveById($identifier): ?Authenticatable
    {
        // Like any provider of an app's own, it knows what its IDs look like:
        // PostgreSQL refuses to compare an email address with a number.
        return is_numeric($identifier) ? $this->users->retrieveById($identifier) : null;
    }

    public function retrieveByToken($identifier, #[\SensitiveParameter] $token): ?Authenticatable
    {
        return $this->users->retrieveByToken($identifier, $token);
    }

    public function updateRememberToken(Authenticatable $user, #[\SensitiveParameter] $token): void
    {
        if ($user instanceof Model) {
            $this->users->updateRememberToken($user, $token);
        }
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        return $this->users->retrieveByCredentials($credentials);
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function validateCredentials(Authenticatable $user, #[\SensitiveParameter] array $credentials): bool
    {
        return $this->users->validateCredentials($user, $credentials);
    }

    /**
     * @param  array<string, mixed>  $credentials
     */
    public function rehashPasswordIfRequired(Authenticatable $user, #[\SensitiveParameter] array $credentials, bool $force = false): void
    {
        if ($user instanceof Model) {
            $this->users->rehashPasswordIfRequired($user, $credentials, $force);
        }
    }
}
