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
 * Sign in with Bitbucket Cloud. The subject is the account's UUID, which
 * never changes: a nickname can. The address is the primary one, and only
 * verified when Bitbucket says it's confirmed, which takes the consumer's
 * "email" permission. Without it, there's no address. Only the first page
 * of /user/emails is read, ten addresses: an account whose primary
 * address isn't among them signs in with none.
 */
class BitbucketProvider extends OAuth2Provider
{
    public const string ISSUER = 'https://bitbucket.org';

    public const string API = 'https://api.bitbucket.org/2.0';

    protected function defaultLabel(): string
    {
        return 'Bitbucket';
    }

    protected function authorizationEndpoint(): string
    {
        return 'https://bitbucket.org/site/oauth2/authorize';
    }

    protected function tokenEndpoint(): string
    {
        return 'https://bitbucket.org/site/oauth2/access_token';
    }

    protected function defaultScopes(): array
    {
        return ['account', 'email'];
    }

    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        $user = $this->api($tokens['access_token'], '/user');

        if (! is_string($user['uuid'] ?? null) || $user['uuid'] === '') {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s user API named no account.");
        }

        $email = null;
        $verified = false;

        foreach ($this->api($tokens['access_token'], '/user/emails', optional: true)['values'] ?? [] as $address) {
            if (is_array($address) && ($address['is_primary'] ?? null) === true && is_string($address['email'] ?? null)) {
                $email = $address['email'];
                $verified = ($address['is_confirmed'] ?? null) === true;
            }
        }

        return new Identity(
            request: $request,
            provider: $this->name,
            issuer: self::ISSUER,
            subject: $user['uuid'],
            email: $email,
            emailVerified: $verified,
            name: is_string($user['display_name'] ?? null) ? $user['display_name'] : null,
            claims: $user,
        );
    }

    /**
     * What the API answers at $path. Bitbucket answers a 403 for a
     * permission the consumer doesn't have, which is no answer at all for
     * an $optional one.
     *
     * @return array<array-key, mixed>
     *
     * @throws SsoFailed
     */
    protected function api(string $token, string $path, bool $optional = false): array
    {
        try {
            $response = Metadata::http()->withToken($token)->get(self::API.$path);
        } catch (Throwable) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s API could not be read at [{$path}].");
        }

        if ($optional && $response->forbidden()) {
            return [];
        }

        $body = $response->successful() ? $response->json() : null;

        if (! is_array($body)) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s API could not be read at [{$path}].");
        }

        return $body;
    }
}
