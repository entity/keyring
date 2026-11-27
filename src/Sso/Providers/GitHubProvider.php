<?php

declare(strict_types=1);

namespace Keyring\Sso\Providers;

use Illuminate\Http\Client\PendingRequest;
use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\SsoFailed;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\Metadata;
use Throwable;

/**
 * Sign in with GitHub, an OAuth app or a GitHub App's user authorization.
 * GitHub doesn't speak OpenID Connect, so there's no ID token: who signed
 * in is whoever the access token reads back from its API.
 *
 * The subject is the account's numeric ID. A login can be renamed, and the
 * old name taken by someone else. An address is only verified when it's
 * the primary one and GitHub says it's verified, which takes the
 * "user:email" scope: without it, the profile's public address, if any, is
 * kept unverified.
 */
class GitHubProvider extends OAuth2Provider
{
    public const string ISSUER = 'https://github.com';

    public const string API = 'https://api.github.com';

    protected function defaultLabel(): string
    {
        return 'GitHub';
    }

    protected function authorizationEndpoint(): string
    {
        return 'https://github.com/login/oauth/authorize';
    }

    protected function tokenEndpoint(): string
    {
        return 'https://github.com/login/oauth/access_token';
    }

    protected function defaultScopes(): array
    {
        return ['read:user', 'user:email'];
    }

    /**
     * GitHub takes the client's credentials in the form, as its own
     * documentation sends them.
     */
    protected function authMethod(): string
    {
        return 'client_secret_post';
    }

    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        $user = $this->api($tokens['access_token'], '/user');

        if (! is_int($user['id'] ?? null) || $user['id'] < 1) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s user API named no account.");
        }

        $email = is_string($user['email'] ?? null) ? $user['email'] : null;
        $verified = false;

        // GitHub lists the scopes it granted with commas, which may be
        // fewer than were asked for.
        $granted = array_map(trim(...), explode(',', is_string($tokens['scope'] ?? null) ? $tokens['scope'] : ''));

        if (array_intersect($granted, ['user:email', 'user']) !== []) {
            foreach ($this->api($tokens['access_token'], '/user/emails') as $address) {
                if (is_array($address) && ($address['primary'] ?? null) === true && is_string($address['email'] ?? null)) {
                    $email = $address['email'];
                    $verified = ($address['verified'] ?? null) === true;
                }
            }
        }

        return new Identity(
            request: $request,
            provider: $this->name,
            issuer: self::ISSUER,
            subject: (string) $user['id'],
            email: $email,
            emailVerified: $verified,
            name: is_string($user['name'] ?? null) ? $user['name'] : (is_string($user['login'] ?? null) ? $user['login'] : null),
            claims: $user,
        );
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws SsoFailed
     */
    protected function api(string $token, string $path): array
    {
        try {
            $body = $this->client($token)->get(self::API.$path)->throw()->json();
        } catch (Throwable) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s API could not be read at [{$path}].");
        }

        if (! is_array($body)) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s API did not answer with JSON at [{$path}].");
        }

        return $body;
    }

    protected function client(string $token): PendingRequest
    {
        return Metadata::http()->withToken($token)->withHeaders([
            'Accept' => 'application/vnd.github+json',
            'X-GitHub-Api-Version' => '2022-11-28',
        ]);
    }
}
