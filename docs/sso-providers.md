# More Identity Providers

- [Introduction](#introduction)
- [Picking a Freshness](#picking-a-freshness)
- [OpenID Connect Providers](#openid-connect-providers)
    - [GitLab](#gitlab)
    - [Slack](#slack)
    - [Twitch](#twitch)
    - [Okta](#okta)
    - [Auth0](#auth0)
    - [Keycloak](#keycloak)
    - [Amazon Cognito](#amazon-cognito)
    - [Salesforce](#salesforce)
- [OAuth 2.0 Providers](#oauth-20-providers)
    - [Registering a Driver](#registering-a-driver)
    - [Discord](#discord)
    - [Bitbucket](#bitbucket)
    - [Facebook](#facebook)
    - [LinkedIn](#linkedin)
    - [Writing Your Own](#writing-your-own)
- [Not Supported](#not-supported)
    - [Sign in with Apple](#sign-in-with-apple)

## Introduction

[Single Sign-On](sso.md) covers Google, Microsoft, and GitHub, which Keyring has drivers for. This page covers the rest. Where Socialite has a community package for each provider, Keyring needs none: most providers speak OpenID Connect, and work with the `oidc` driver and a few lines of config. A provider that only speaks OAuth 2.0 needs a small driver of your own, built on `OAuth2Provider`, as Keyring's GitHub driver is.

The endpoints, scopes, and claims on this page were checked against each provider's documentation and its live discovery document on 27 November 2026, and each example runs in Keyring's test suite against a fake of the provider. Providers change these things, and nobody here has signed in at most of them for real. Where something couldn't be confirmed, the section says so: check it against the provider's current docs before you rely on it.

| Provider | How | `freshness` |
|---|---|---|
| [GitLab](#gitlab) | `oidc` | `never` |
| [Slack](#slack) | `oidc` | `never` |
| [Twitch](#twitch) | `oidc` | `never` |
| [Okta](#okta) | `oidc` | `reauthenticate` (the default) |
| [Auth0](#auth0) | `oidc` | `reauthenticate` (the default) |
| [Keycloak](#keycloak) | `oidc` | `reauthenticate` (the default) |
| [Amazon Cognito](#amazon-cognito) | `oidc` | `reauthenticate` with managed login, `never` with the classic hosted UI |
| [Salesforce](#salesforce) | `oidc` | `never` |
| [Discord](#discord), [Bitbucket](#bitbucket), [Facebook](#facebook), [LinkedIn](#linkedin) | a driver | `never` (the default for `OAuth2Provider`) |
| [Apple](#sign-in-with-apple) | not supported | |

## Picking a Freshness

A provider's [`freshness`](sso.md#freshness) says how much a sign in or a confirm through it counts toward `keyring.fresh`. The `oidc` driver's default, `reauthenticate`, only works with a provider that does two things:

- It puts `auth_time`, when the user last signed in there, in its ID tokens. Keyring asks for it with the `claims` parameter when discovery lists `claims_parameter_supported`. Otherwise the provider has to send it unasked, or at least for `max_age`, as OpenID Connect says it should.
- It signs the user in again when a confirm asks it to, with `prompt=login` and `max_age=0`, and sends an `auth_time` from then.

With a provider that does neither, `reauthenticate` is worse than `never`: no sign in through it is ever fresh, and the confirm page offers a link that always fails with `StaleAuthentication`. So for a provider that doesn't document both, set `'freshness' => 'never'`, and users confirm with their password or another method. Only opt a provider into `round_trip` after reading [what that gives away](sso.md#freshness).

A broker, such as Okta, Auth0, Keycloak or Cognito, needs one more thing for `reauthenticate` to mean anything: the user has to type their credentials at the broker itself. When they sign in there through a federated connection, such as Auth0's `google-oauth2` or a Keycloak identity provider, the broker passes `prompt=login` on, or doesn't, and the upstream provider may let the user straight through on its own session, with one click. The broker then stamps a new `auth_time` all the same, so a confirm counts as fresh when nobody typed anything. So only keep `reauthenticate` for a broker where every user signs in with the broker's own credentials, or where every upstream connection is set to make the user sign in again. Otherwise use `never`.

Whichever you pick, check it before you rely on it. In one browser, sign in through the provider, wait a few minutes, then sign out of your app and sign in through the provider again, as a user of each connection would. If the second ID token's `auth_time` is the first one's, the provider counts the old session, as it should. If it moved, the provider stamps sign ins it let straight through as new ones, so it can't be trusted with `reauthenticate`. Then confirm a `keyring.fresh` page with it: you should be asked to sign in again at the provider, and at any upstream one.

## OpenID Connect Providers

Every provider here takes the [callback URL](sso.md#the-callback-url), `https://example.com/auth/{provider}/callback`, with the provider's name in `sso.providers` in place of `{provider}`. Keyring asks for the `openid`, `email`, and `profile` scopes unless the config's `scopes` says otherwise, and always adds `openid`. It finds the endpoints from `{issuer}/.well-known/openid-configuration`, and the issuer has to match the one in that document exactly, trailing slash and all.

Keyring requires every ID token to carry the `nonce` it sent. That's what keeps LinkedIn out of this list: its ID tokens are [reported](#linkedin) to leave it out.

### GitLab

In GitLab, open your user settings, or a group's settings, and add an application under **Applications**. Set its redirect URI to the callback URL, keep it **Confidential**, and tick the `openid`, `profile`, and `email` scopes:

```php
'gitlab' => [
    'driver' => 'oidc',
    'name' => 'GitLab',
    'issuer' => 'https://gitlab.com',
    'freshness' => 'never',
    'client_id' => env('GITLAB_CLIENT_ID'),
    'client_secret' => env('GITLAB_CLIENT_SECRET'),
],
```

For a self-managed instance, the issuer is the instance's URL, such as `https://gitlab.example.com`.

The subject is the user's numeric ID. GitLab only sends `email` and `email_verified` with the `email` scope, or when the user has a public address. Without either, the identity has no address.

Set `'freshness' => 'never'`. GitLab's ID tokens do carry `auth_time`, but it's when the user last signed in on any device, not in this browser. A sign in through an old GitLab session in this browser would count as fresh whenever the user had recently signed in at GitLab somewhere else, so `reauthenticate` can't be trusted for sign ins. A confirm through GitLab would be sound, since its source signs the user out and in again for `prompt=login`, but `reauthenticate` covers both, and wasn't tried against GitLab.com. With `never`, users confirm with a password or another method instead.

### Slack

Create a Slack app, and under **OAuth & Permissions** add the callback URL as a redirect URL. Slack expects HTTPS redirect URLs, so while developing, you may need a tunnel. Sign in with Slack uses the app's client ID and secret from **Basic Information**:

```php
'slack' => [
    'driver' => 'oidc',
    'name' => 'Slack',
    'issuer' => 'https://slack.com',
    'client_id' => env('SLACK_CLIENT_ID'),
    'client_secret' => env('SLACK_CLIENT_SECRET'),
    'freshness' => 'never',
],
```

Slack's token endpoint, `openid.connect.token`, is one of its Web API methods, so it answers with `"ok": true` beside the tokens, and refuses a code with a `200` and `"ok": false, "error": "invalid_code"`. Keyring reads both as it should: the extra field is ignored, and the error is a failed exchange.

The subject is the Slack user ID, such as `U0R7JM`, which Slack now says is unique across workspaces. The workspace is in the `https://slack.com/team_id` claim, if you only want to let in one, which a [custom driver](sso.md#custom-drivers) can check. Slack gives a user in an Enterprise organisation a new ID when their workspace joins it, so they'd link Slack again afterwards. To skip the workspace picker, add `'parameters' => ['team' => 'T0123ABC456']`.

Slack's ID token has an `auth_time`, but Slack doesn't document `prompt=login` or `max_age`, so a confirm can't make anyone sign in again, and would fail with `StaleAuthentication` whenever the user is still signed in at Slack. Hence `'freshness' => 'never'`.

### Twitch

Register an application in the Twitch developer console, with the callback URL as its OAuth redirect URL, and make it a **Confidential** client:

```php
'twitch' => [
    'driver' => 'oidc',
    'name' => 'Twitch',
    'issuer' => 'https://id.twitch.tv/oauth2',
    'client_id' => env('TWITCH_CLIENT_ID'),
    'client_secret' => env('TWITCH_CLIENT_SECRET'),
    'scopes' => ['openid', 'user:read:email'],
    'parameters' => ['claims' => '{"id_token":{"email":null,"email_verified":null}}'],
    'freshness' => 'never',
],
```

Twitch has no `email` or `profile` scopes. Its ID token only carries the address when the request asks for it with the `claims` parameter and the `user:read:email` scope, as above, and it leaves `email_verified` out when the address isn't verified, which Keyring reads as unverified. The subject is the Twitch user ID, which stays the same when the user changes their login name.

Twitch's discovery only lists `client_secret_post`, so Keyring sends the secret in the form without being told. It doesn't document `prompt=login` or `max_age`, and doesn't list `auth_time` among its claims, so set `'freshness' => 'never'`.

### Okta

In the Okta admin console, create an app integration under **Applications**: **OIDC - OpenID Connect**, **Web Application**, with the authorization code grant, and the callback URL as a sign-in redirect URI:

```php
'okta' => [
    'driver' => 'oidc',
    'name' => 'Okta',
    'issuer' => 'https://example.okta.com',
    'client_id' => env('OKTA_CLIENT_ID'),
    'client_secret' => env('OKTA_CLIENT_SECRET'),
],
```

That's the org authorization server. With a custom authorization server, the issuer has its path too, such as `https://example.okta.com/oauth2/default`. Check the issuer shown under **Security**, **API**, and use it as written. Users signed in through one aren't the same accounts to Keyring as through the other, since the issuer is part of who they are.

The subject is the Okta user's ID (`00u...`). Okta puts `auth_time` in every ID token and takes `prompt=login` and `max_age`, so the default `reauthenticate` works.

That holds while users sign in with Okta's own credentials. Where they come through an external identity provider, a federated connection, Okta may let them through on the upstream session and stamp a new `auth_time`, so use `never` unless every such connection forces a new sign in, as [Picking a Freshness](#picking-a-freshness) says, and check it there.

### Auth0

In the Auth0 dashboard, create a **Regular Web Application**, and add the callback URL to its **Allowed Callback URLs**:

```php
'auth0' => [
    'driver' => 'oidc',
    'name' => 'Auth0',
    'issuer' => 'https://example.us.auth0.com/',
    'client_id' => env('AUTH0_CLIENT_ID'),
    'client_secret' => env('AUTH0_CLIENT_SECRET'),
],
```

Auth0's issuer ends in a slash, and Keyring refuses the discovery document without it. With a custom domain, the issuer is that domain, such as `https://login.example.com/`.

Under the application's **Advanced Settings**, **OAuth**, the **JSON Web Token Signature Algorithm** has to be `RS256` (or `PS256`). An application signing with `HS256` is refused, since Keyring never checks a token against a shared secret.

The subject names the connection the user signed in with, such as `auth0|64f1...` or `google-oauth2|1098...`, so the same person through two connections is two accounts, unless you link them in Auth0. `email_verified` is whatever the connection says.

Auth0 takes `prompt=login` and `max_age`, and sends `auth_time` for them, so a confirm works with the default `reauthenticate`. Its discovery doesn't list `claims_parameter_supported`, so Keyring can't ask for `auth_time` on an ordinary sign in. If your tenant's ID tokens leave it out, no sign in through Auth0 is fresh, and users confirm at Auth0 before their first `keyring.fresh` action.

That holds for Auth0's database connections, where users type their password at Auth0. Through a social or enterprise connection, such as `google-oauth2`, `prompt=login` can go straight through on the user's Google session with one click, and Auth0 still stamps `auth_time` as now. So with any connection besides a database one, use `never`, unless every one of them is set to make the user sign in again, as [Picking a Freshness](#picking-a-freshness) says, and check it there.

### Keycloak

In the realm, create an OpenID Connect client with **Client authentication** on and the **Standard flow**, and add the callback URL to its **Valid redirect URIs**:

```php
'keycloak' => [
    'driver' => 'oidc',
    'name' => 'Keycloak',
    'issuer' => 'https://keycloak.example.com/realms/acme',
    'client_id' => env('KEYCLOAK_CLIENT_ID'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
],
```

The issuer is the realm's URL, `{host}/realms/{realm}`. While developing, Keycloak can run in Docker on `http://localhost:8080`, since Keyring takes plain HTTP for `localhost`. The subject is the Keycloak user's ID.

Keyring's own integration suite signs in at a real Keycloak, and the default `reauthenticate` works there in full: `auth_time` through the `claims` parameter, `prompt=login`, and the `iss` parameter on the callback (RFC 9207), which Keyring then requires. That's with users signing in with Keycloak's own credentials. A realm that brokers another identity provider can send users there and back on its session, and still set `auth_time` to now, so for such a realm use `never`, unless every brokered provider is made to ask for a new sign in, as [Picking a Freshness](#picking-a-freshness) says, and check it there.

### Amazon Cognito

In the user pool, add a domain, then an app client with a client secret, the authorization code grant, the `openid`, `email`, and `profile` scopes, and the callback URL as an allowed callback URL. Cognito takes `http://localhost` callback URLs for testing:

```php
'cognito' => [
    'driver' => 'oidc',
    'name' => 'Acme',
    'issuer' => 'https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_AbCdEf123',
    'client_id' => env('COGNITO_CLIENT_ID'),
    'client_secret' => env('COGNITO_CLIENT_SECRET'),
    'freshness' => 'never',
],
```

The issuer is `https://cognito-idp.{region}.amazonaws.com/{userPoolId}`, not the pool's domain. Its discovery document is served there, and names the endpoints on the domain, where users sign in. The subject is the Cognito user's `sub`, a UUID.

Cognito's ID tokens carry `auth_time`, but whether a confirm can make the user sign in again depends on the pool's branding. Managed login takes `prompt=login` and `max_age`. The classic hosted UI silently ignores `max_age` and `prompt`, so a confirm there lets a user with a Cognito session straight through, and Keyring refuses it with `StaleAuthentication`. So:

- With **managed login**, and users who sign in with the pool's own credentials, remove `'freshness' => 'never'` to get the default `reauthenticate`.
- With the **classic hosted UI**, keep `never`, as above, and users confirm with another method.
- With a federated identity provider in the pool, such as Google or a SAML provider, keep `never` too, unless each of them is made to ask for a new sign in: Cognito may send the user there and back on its session and still stamp a new `auth_time`. See [Picking a Freshness](#picking-a-freshness), and check it there.

### Salesforce

Create a connected app, or an external client app, with OAuth turned on, the callback URL, and the `openid`, `email`, and `profile` scopes. Turn on **Require Proof Key for Code Exchange (PKCE)**, since Keyring always sends one:

```php
'salesforce' => [
    'driver' => 'oidc',
    'name' => 'Salesforce',
    'issuer' => 'https://login.salesforce.com',
    'client_id' => env('SALESFORCE_CLIENT_ID'),
    'client_secret' => env('SALESFORCE_CLIENT_SECRET'),
    'freshness' => 'never',
],
```

For a sandbox, the issuer is `https://test.salesforce.com`. To sign in at your org's My Domain, use it, such as `https://acme.my.salesforce.com`. The issuer in the ID token has to be the one configured, so check which one your org's tokens carry when users sign in through My Domain.

The subject is the user's identity URL, such as `https://login.salesforce.com/id/00D5e000000abcdEAA/0055e000001AbCdAAK`, which names their org and user. Salesforce documents `prompt=login`, but its discovery doesn't list `auth_time`, so set `'freshness' => 'never'`.

> [!WARNING]
> Salesforce's ID tokens once said `email_verified` was `true` for every user, whatever its userinfo endpoint said (known issue W-4338099, marked fixed in Winter '18), and whether an address counts as verified depends on how the user was set up. Keyring never matches on the address, but if your own code [signs people up](sso.md#signing-up-with-a-provider) with it, check `email_verified` against Salesforce's userinfo endpoint before trusting it.

## OAuth 2.0 Providers

A provider without OpenID Connect has no ID token, so a driver reads who signed in from the provider's API, with the access token, as Keyring's GitHub driver does. `OAuth2Provider` handles the state, PKCE, the code exchange, and client authentication. A driver gives it the endpoints and scopes, and turns the tokens into an `Identity`. Its [`freshness`](sso.md#freshness) is `never` unless the config says otherwise, since plain OAuth 2.0 can't ask for a new sign in, nor say when there was one.

Each driver below keeps the account's permanent ID as the subject, never a username or an address, and only sets `emailVerified` when the provider's API says the address is verified.

### Registering a Driver

Put the class in your app, such as `app/Sso/DiscordProvider.php`, and register it in your `KeyringServiceProvider`'s `boot()` method:

```php
use App\Sso\DiscordProvider;
use Keyring\Facades\Keyring;

Keyring::sso()->extend('discord', fn (array $config, string $name) => new DiscordProvider($name, $config));
```

Then use it as the `driver` in `sso.providers`:

```php
'discord' => [
    'driver' => 'discord',
    'client_id' => env('DISCORD_CLIENT_ID'),
    'client_secret' => env('DISCORD_CLIENT_SECRET'),
],
```

Every option in [Configuration](sso.md#configuration) works with it, apart from `issuer` and `tenant`. The issuer is a constant of the driver's. Never change it once users have linked accounts, since a link is the pair of the issuer and the subject.

### Discord

In the Discord developer portal, open the application, and add the callback URL as a redirect under **OAuth2**:

```php
namespace App\Sso;

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
```

Discord's [user object](https://docs.discord.com/developers/resources/user) has the `email` and `verified` fields only with the `email` scope. Its token endpoint takes the secret in a header or the form, and an S256 PKCE verifier.

### Bitbucket

In the Bitbucket workspace's settings, add an OAuth consumer under **OAuth consumers**, with the callback URL, and the **Account: Email** and **Account: Read** permissions:

```php
namespace App\Sso;

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
```

`GET /2.0/user` needs the `account` permission, and gives the account's `uuid`, such as `{d301aafa-d676-4ee0-88be-962be7417567}`. `GET /2.0/user/emails` needs `email`, and lists every address, confirmed or not. A consumer's permissions are set on the consumer, which may be fewer than the `scope` Keyring asks for. Check these against the provider's current docs:

- Keyring sends a PKCE challenge, a `scope`, and the `redirect_uri` with every request, and Bitbucket's OAuth guide documents none of them. Bitbucket is expected to ignore the PKCE parameters, but try a sign in before you ship it.
- The address fields, `is_primary` and `is_confirmed` inside a paged `values` list, aren't in Bitbucket's current API reference, though its API has long answered with them.
- The account's `account_id`, its Atlassian account ID, is permanent too. The driver keeps the `uuid`, which Bitbucket's reference documents for every account.

### Facebook

In the Meta developer dashboard, create an app with **Facebook Login**, and add the callback URL to its **Valid OAuth Redirect URIs**. While the app is in development mode, Facebook takes `localhost` redirects without listing them:

```php
namespace App\Sso;

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
```

The [user](https://developers.facebook.com/docs/graph-api/reference/user/) `id` is app-scoped: "unique to the app and cannot be used by other apps". Moving to another Facebook app gives every user a new ID, so they'd link Facebook again. Facebook has no field that says the address is verified, so `emailVerified` is always `false`, and an app that [signs people up](sso.md#signing-up-with-a-provider) with Facebook has to verify the address itself. Check these against the provider's current docs:

- Facebook's [manual login flow](https://developers.facebook.com/docs/facebook-login/guides/advanced/manual-flow) documents the code exchange as a `GET` with the secret in the query string. `OAuth2Provider` sends it as a `POST` form, which the Graph API takes for the same endpoint, but try it.
- The manual flow doesn't document PKCE, so Facebook is expected to ignore the challenge.
- An app with **Require App Secret** turned on needs an `appsecret_proof` with every Graph API call. Add it to the `/me` request's query, as `hash_hmac('sha256', $tokens['access_token'], $this->config['client_secret'])`.
- Graph API versions expire after about two years. Move `v27.0` on when Meta asks.

### LinkedIn

LinkedIn speaks OpenID Connect, but several projects, including Keycloak, report that its ID tokens leave out the `nonce` the request sent, which Keyring's `oidc` driver requires. So this driver reads who signed in from LinkedIn's userinfo endpoint with the access token instead, the way the [Sign In with LinkedIn using OpenID Connect](https://learn.microsoft.com/en-us/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2) docs also describe. In the LinkedIn developer portal, add that product to your app, and add the callback URL under **Auth**:

```php
namespace App\Sso;

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
```

LinkedIn's `sub` is pairwise: the same member has a different one in each app, so moving to another LinkedIn app means linking again. The `email` and `email_verified` fields are optional, and an identity without `email_verified` is unverified. LinkedIn's own docs say Sign In with LinkedIn "does not verify user identities", so treat it as proof of a LinkedIn account and nothing more. Check these against the provider's current docs:

- The issuer is the one LinkedIn's live discovery document names, `https://www.linkedin.com/oauth`. Its docs still show `https://www.linkedin.com`, which its tokens stopped carrying in 2024. Since this driver reads no ID token, the issuer is only the name its links are kept under, so pick it once and leave it.
- LinkedIn documents PKCE only for native apps. Keyring always sends a challenge, and LinkedIn's token endpoint mentions the code verifier in its errors, so it's expected to check it. Try a sign in.
- LinkedIn's guide says to register HTTPS redirect URLs, so you may need a tunnel while developing.

### Writing Your Own

Any other OAuth 2.0 provider follows the same shape. Extend `Keyring\Sso\Providers\OAuth2Provider`, and:

1. Return the provider's endpoints from `authorizationEndpoint()` and `tokenEndpoint()`, and its scopes from `defaultScopes()`. Override `defaultLabel()` with the name for the button.
2. Override `authMethod()` to return `client_secret_post` when the provider only takes the secret in the form. The default is a `Basic` header.
3. In `identityFrom()`, read the user with `Metadata::http()->withToken($tokens['access_token'])`. It has short timeouts and follows no redirects, so a provider can't hand the token somewhere else. Turn any failure into `SsoFailed::because(SsoFailure::Unavailable, ...)`, without the token in the message.
4. Use the account's permanent ID as the `subject`: one that never changes and is never reused. Never a username, a handle, or an address, which can change and be taken by someone else. Check the provider's docs for which field that is. Spotify's, for example, says to link on `account_id`, not `id`.
5. Pick one `ISSUER` for the provider, such as its website, and never change it.
6. Set `emailVerified` to `true` only when the provider's API says that address is verified, and treat anything else, a missing field or a string `"true"`, as `false`. Many providers, such as Facebook and Spotify, never say, and then it's always `false`.
7. Leave `freshness()` alone: `never` is right for a provider that can't be asked for a new sign in, and `supportsReauthentication()` stays `false`.
8. If the provider answers a refused code with a `200` and an `error` in the body, as GitHub and Slack do, `OAuth2Provider` already reads that as a failed exchange.
9. Test it as Keyring's own tests for these examples do (`tests/Feature/Sso/DocsExamplesTest.php`): `Http::fake()` the token endpoint and the API with the bodies from the provider's docs, and check the subject, a verified, an unverified and a missing address, and a missing scope.

`OAuth2Provider` only reads the callback from the query string, so a provider has to send the user back with a `GET`.

## Not Supported

### Sign in with Apple

Keyring doesn't support Sign in with Apple, for two reasons:

- When a request asks for the user's name or address, Apple requires `response_mode=form_post`, and sends the user back with a `POST` from `appleid.apple.com`. Keyring never uses `form_post`: the callback finds the request in the session, and the session cookie is `SameSite=Lax`, which a browser leaves off a cross-site `POST`. So the callback can't tell which browser started the sign in. Making the cookie `SameSite=None` for it would weaken every other request your app takes.
- Apple's client secret isn't a fixed string, but a JWT your server signs with its Sign in with Apple key, which lasts six months at most.

Without the name and email scopes, Apple sends the user back with a plain `GET` and an ID token holding only the subject, which the `oidc` driver could take, with a client secret your app signs and refreshes on a schedule. Nobody has tried that against Apple, and an app usually wants the address, so it's out of scope for now. An app that needs Apple today has to handle it outside Keyring's single sign-on, and has to tie Apple's `POST` back to the browser that started it some other way than the session.
