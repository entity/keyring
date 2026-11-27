<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures\Sso;

use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\SsoFailed;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\Metadata;
use Keyring\Sso\Providers\OAuth2Provider;
use Throwable;

/**
 * Sign in with Discord. The subject is the account's ID, a snowflake that
 * never changes: a username can be changed, and taken by someone else.
 */
class DiscordProvider extends OAuth2Provider
{
    public const string ISSUER = 'https://discord.com';

    protected function defaultLabel(): string
    {
        return 'Discord';
    }

    protected function authorizationEndpoint(): string
    {
        return 'https://discord.com/oauth2/authorize';
    }

    protected function tokenEndpoint(): string
    {
        return 'https://discord.com/api/oauth2/token';
    }

    protected function defaultScopes(): array
    {
        return ['identify', 'email'];
    }

    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        try {
            $user = Metadata::http()->withToken($tokens['access_token'])
                ->get('https://discord.com/api/v10/users/@me')
                ->throw()
                ->json();
        } catch (Throwable) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s user API could not be read.");
        }

        if (! is_array($user) || ! is_string($user['id'] ?? null) || ! ctype_digit($user['id'])) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s user API named no account.");
        }

        // Only with the "email" scope: the address, which may be null, and
        // "verified", whether Discord has verified it.
        $email = is_string($user['email'] ?? null) ? $user['email'] : null;

        return new Identity(
            request: $request,
            provider: $this->name,
            issuer: self::ISSUER,
            subject: $user['id'],
            email: $email,
            emailVerified: $email !== null && ($user['verified'] ?? null) === true,
            name: match (true) {
                is_string($user['global_name'] ?? null) => $user['global_name'],
                is_string($user['username'] ?? null) => $user['username'],
                default => null,
            },
            claims: $user,
        );
    }
}
