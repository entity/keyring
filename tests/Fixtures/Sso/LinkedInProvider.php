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
 * Sign in with LinkedIn, reading who signed in from its userinfo endpoint
 * rather than its ID token, which leaves out the nonce Keyring's OpenID
 * Connect driver requires. The subject is LinkedIn's "sub", which is only
 * the same for this app.
 */
class LinkedInProvider extends OAuth2Provider
{
    public const string ISSUER = 'https://www.linkedin.com/oauth';

    protected function defaultLabel(): string
    {
        return 'LinkedIn';
    }

    protected function authorizationEndpoint(): string
    {
        return 'https://www.linkedin.com/oauth/v2/authorization';
    }

    protected function tokenEndpoint(): string
    {
        return 'https://www.linkedin.com/oauth/v2/accessToken';
    }

    protected function defaultScopes(): array
    {
        return ['openid', 'profile', 'email'];
    }

    /**
     * LinkedIn takes the client secret in the form.
     */
    protected function authMethod(): string
    {
        return 'client_secret_post';
    }

    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        try {
            $user = Metadata::http()->withToken($tokens['access_token'])
                ->get('https://api.linkedin.com/v2/userinfo')
                ->throw()
                ->json();
        } catch (Throwable) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s userinfo endpoint could not be read.");
        }

        if (! is_array($user) || ! is_string($user['sub'] ?? null) || $user['sub'] === '') {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s userinfo endpoint named no account.");
        }

        $email = is_string($user['email'] ?? null) ? $user['email'] : null;

        return new Identity(
            request: $request,
            provider: $this->name,
            issuer: self::ISSUER,
            subject: $user['sub'],
            email: $email,
            emailVerified: $email !== null && ($user['email_verified'] ?? null) === true,
            name: is_string($user['name'] ?? null) ? $user['name'] : null,
            claims: $user,
        );
    }
}
