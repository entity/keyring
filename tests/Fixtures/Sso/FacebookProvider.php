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
 * Sign in with Facebook. The subject is the app-scoped user ID, which never
 * changes for this app, but is a different one in another app. Facebook
 * doesn't say whether the address is verified, so it never is.
 */
class FacebookProvider extends OAuth2Provider
{
    public const string ISSUER = 'https://www.facebook.com';

    public const string GRAPH = 'https://graph.facebook.com/v27.0';

    protected function defaultLabel(): string
    {
        return 'Facebook';
    }

    protected function authorizationEndpoint(): string
    {
        return 'https://www.facebook.com/v27.0/dialog/oauth';
    }

    protected function tokenEndpoint(): string
    {
        return self::GRAPH.'/oauth/access_token';
    }

    protected function defaultScopes(): array
    {
        return ['public_profile', 'email'];
    }

    /**
     * Facebook takes the app secret as a parameter, not in a header.
     */
    protected function authMethod(): string
    {
        return 'client_secret_post';
    }

    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        try {
            $user = Metadata::http()->withToken($tokens['access_token'])
                ->get(self::GRAPH.'/me', ['fields' => 'id,name,email'])
                ->throw()
                ->json();
        } catch (Throwable) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s Graph API could not be read.");
        }

        if (! is_array($user) || ! is_string($user['id'] ?? null) || ! ctype_digit($user['id'])) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s Graph API named no account.");
        }

        return new Identity(
            request: $request,
            provider: $this->name,
            issuer: self::ISSUER,
            subject: $user['id'],
            // Only with the "email" permission, and only when the account
            // has an address Facebook considers valid.
            email: is_string($user['email'] ?? null) ? $user['email'] : null,
            emailVerified: false,
            name: is_string($user['name'] ?? null) ? $user['name'] : null,
            claims: $user,
        );
    }
}
