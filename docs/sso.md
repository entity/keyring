# Single Sign-On

- [Introduction](#introduction)
- [Setting Up](#setting-up)
    - [The Callback URL](#the-callback-url)
    - [Google](#google)
    - [Microsoft](#microsoft)
    - [GitHub](#github)
    - [Any OpenID Connect Provider](#any-openid-connect-provider)
- [Configuration](#configuration)
    - [Freshness](#freshness)
- [Login Buttons](#login-buttons)
- [Linking and Unlinking](#linking-and-unlinking)
- [How It Fits With the Rest](#how-it-fits-with-the-rest)
    - [Second Factors and Policies](#second-factors-and-policies)
    - [Hearing About Accepted Identities](#hearing-about-accepted-identities)
    - [Step-Up](#step-up)
    - [Users Whose Only Way In Is Never Fresh](#users-whose-only-way-in-is-never-fresh)
    - [Password Resets and Email Changes](#password-resets-and-email-changes)
    - [Failures and the Security Log](#failures-and-the-security-log)
- [No Sign Up, and No Linking by Email](#no-sign-up-and-no-linking-by-email)
    - [Signing Up With a Provider](#signing-up-with-a-provider)
- [Frontends Laravel Doesn't Serve](#frontends-laravel-doesnt-serve)
- [Security Notes](#security-notes)
- [Custom Drivers](#custom-drivers)
- [Testing](#testing)
- [Migrating From the Socialite Recipe](#migrating-from-the-socialite-recipe)

## Introduction

Keyring can sign users in with an identity provider: "Sign in with Google", "Sign in with Microsoft", "Sign in with GitHub", or any OpenID Connect provider, such as Okta, Auth0, Keycloak, or your own. It's a factor like any other, `Keyring\Factors\SingleSignOn`, so you don't need Socialite or another package. To turn it on, add it to your factors:

```php
use Keyring\Facades\Keyring;
use Keyring\Factors;

Keyring::factors([
    Factors\Password::class,
    Factors\Totp::class,
    Factors\RecoveryCodes::class,
    Factors\WebAuthn::passkeys(),
    Factors\SingleSignOn::class,
]);
```

Then list your providers under `sso.providers` in `config/keyring.php`. [More Identity Providers](sso-providers.md) has the config for GitLab, Slack, Twitch, Okta, Auth0, Keycloak, Amazon Cognito, and Salesforce, and drivers for Discord, Bitbucket, Facebook, and LinkedIn.

Each account at a provider that a user links is one of their [authenticators](authenticators.md), with the `sso` factor key. A sign in with a provider goes through the same [pipeline](sign-in-flow.md#the-verification-pipeline) as the login form. That means rate limits, your policy, risk checks, devices, and sessions all apply, and a user with a second factor is still asked for it.

Keyring matches the account the provider vouched for on its issuer and subject, never on its email address. Nobody is signed up or linked by their address: a user links an account at a provider from your settings page, while signed in, before it can sign them in. See [No Sign Up, and No Linking by Email](#no-sign-up-and-no-linking-by-email).

| | |
|---|---|
| Key | `sso` |
| Categories | knowledge: it stands in for the password, so it counts as the same kind of proof |
| Starts a sign in | yes, from the provider's callback |
| Answers a challenge | no |
| Answers a confirm | by going back to the provider, as its [`freshness`](#freshness) says: with `reauthenticate` the user signs in again there, and with `round_trip` it proves as much as signing in with it again would. With `never`, the default for Google and GitHub, it's a plain round trip that counts toward a level such as AAL2, never toward a fresh verification, so it's only offered toward a level. See [Step-Up](#step-up) |
| Users add it | yes, one for each account they link |
| Recovery codes, default | neither: a link never comes with recovery codes, and is never the default |
| Priority | 30 |

## Setting Up

### The Callback URL

Every provider sends the user back to the same URL, whether they're signing in, linking an account, or confirming a step-up:

```
https://example.com/auth/{provider}/callback
```

`{provider}` is the provider's name in `sso.providers`, so a provider named `google` uses `https://example.com/auth/google/callback`. Register that URL with the provider exactly as written. It starts with `APP_URL`, followed by Keyring's route [`prefix`](configuration.md#routes) when you set one. If you call [`Keyring::linkRootUsing()`](security.md#emailed-links), it starts there instead, like the links in Keyring's emails. That's how a [frontend Laravel doesn't serve](#frontends-laravel-doesnt-serve) takes the callback.

While developing, register the local URL too, such as `http://localhost:8000/auth/google/callback`. Most providers take more than one.

The routes are:

| Method | URI | Name | Does |
|---|---|---|---|
| `GET` | `/auth/{provider}/redirect` | `keyring.sso.redirect` | Sends a guest to the provider to sign in. Uses the `keyring-login-options` rate limiter. |
| `GET` | `/auth/{provider}/callback` | `keyring.sso.callback` | Where the provider sends the user back, to sign in, to finish a link, or to confirm. |
| `GET` | `/confirm/sso/redirect` | `keyring.sso.confirm` | Sends a signed-in user back to the provider of a link the confirm page offers, to confirm by signing in there. Takes the link's ID as `authenticator`. Uses the `keyring-login-options` rate limiter. See [Step-Up](#step-up). |
| `POST` | `/user/authenticators/sso` | `keyring.authenticators.store` | Begins a link, with `provider`. See [Linking and Unlinking](#linking-and-unlinking). |

Keyring only registers the `/auth` routes and `/confirm/sso/redirect` when `sso.providers` lists at least one provider as the app boots, so an app without providers keeps any `/auth/...` routes of its own. Once registered, they answer `404` until the `SingleSignOn` factor is registered, and for a provider that isn't configured. With [cached routes](https://laravel.com/docs/deployment#optimizing-route-loading), run `php artisan route:cache` again after adding your first provider.

The callback only finishes Keyring's own sign ins, links, and confirms. A request your own code started with [`Keyring::sso()`](#signing-up-with-a-provider) for anything else is spent there and answered with a `404`, so it can't be finished at Keyring's callback as a sign in. A guest's callback draws on the `keyring-login-options` rate limiter, as the redirect does, and a signed-in user's link or confirm on the `keyring` limiter.

### Google

In the Google Cloud console, create an OAuth client ID of the "Web application" type, and add the callback URL to its authorized redirect URIs. Then add it to `config/keyring.php`:

```php
'sso' => [
    'providers' => [
        'google' => [
            'driver' => 'google',
            'client_id' => env('GOOGLE_CLIENT_ID'),
            'client_secret' => env('GOOGLE_CLIENT_SECRET'),
        ],
    ],
],
```

Keyring asks for the `openid`, `email`, and `profile` scopes. Google's `email_verified` claim can be trusted for Gmail and Workspace addresses. A Workspace account's domain is in the `hd` claim.

Google only says when the user signed in there (`auth_time`) for an app that's published and verified, with "Session age claims" turned on under Settings, Advanced Settings, in the Google Auth Platform, and then only when the request asks for it with the `claims` parameter ([Google's OpenID Connect docs](https://developers.google.com/identity/openid-connect/openid-connect), [Security bundle](https://developers.google.com/identity/siwg/security-bundle)). Google documents no way to have a user sign in again either ("Google does not support Google Account reauth requests"): it takes no `prompt=login`, and doesn't document `max_age`. So Google's [`freshness`](#freshness) is `never` by default: a sign in with Google never counts toward a [fresh verification](step-up.md#fresh-verification), and the confirm page only offers Google links toward a level, never for `keyring.fresh`. Users make protected changes, such as adding a passkey, with their password or another method. A user whose only way in is Google has to [set a password](#users-whose-only-way-in-is-never-fresh) first.

Once your app has session age claims, you can set `'freshness' => 'reauthenticate'`. Keyring then asks for `auth_time` with every sign in, and a sign in counts from when the user last signed in at Google. A confirm sends `max_age=0`, the `claims` parameter, and the link's address as `login_hint`, and only counts when the `auth_time` that comes back is from after the user was sent to Google. Since Google doesn't promise to ask for a new sign in, a user who is still signed in at Google may have to sign out there, or confirm another way.

### Microsoft

In the Microsoft Entra admin center, register an application. Add a "Web" platform with the callback URL as its redirect URI, and create a client secret under "Certificates & secrets":

```php
'microsoft' => [
    'driver' => 'microsoft',
    'tenant' => env('MICROSOFT_TENANT', 'common'),
    'client_id' => env('MICROSOFT_CLIENT_ID'),
    'client_secret' => env('MICROSOFT_CLIENT_SECRET'),
],
```

The `tenant` decides who can sign in:

| `tenant` | Who |
|---|---|
| `common` (the default) | Work and school accounts from any organisation, and personal Microsoft accounts. |
| `organizations` | Work and school accounts from any organisation. A token from the personal accounts tenant is refused. |
| `consumers` | Personal Microsoft accounts. |
| A tenant ID or domain | That one organisation's accounts. |

It has to match the account types the app registration supports. With `common` or `organizations`, each user's account is kept under their own tenant's issuer, so the same subject in two tenants is two people, and as [Microsoft asks of multi-tenant apps](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-the-issuer), a signing key that names an `issuer` only signs tokens whose `iss` it is, with the token's `tid` in place of `{tenantid}`. To let in only some organisations, check the `tid` claim in a [custom driver](#custom-drivers).

Microsoft's [`freshness`](#freshness) is `reauthenticate`: a sign in counts toward a [fresh verification](step-up.md#fresh-verification) from when the user last signed in at Microsoft, and a confirm sends [`prompt=login`](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#send-the-sign-in-request), which Microsoft documents, with the link's address as `login_hint`, but not `max_age`, which it doesn't, and checks the `auth_time` itself. Microsoft only puts `auth_time` in its ID tokens when the app registration adds it as an [optional claim](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims), whatever the request asks, so add it:

1. In the Microsoft Entra admin center, open the app registration and choose **Token configuration**.
2. Choose **Add optional claim**, pick the **ID** token type, tick **auth_time**, and choose **Add**.

Or, in the app registration's **Manifest**, add it to the ID token's optional claims:

```json
"optionalClaims": {
    "idToken": [
        { "name": "auth_time", "source": null, "essential": false, "additionalProperties": [] }
    ]
}
```

Without it, no sign in with Microsoft is ever fresh, and every confirm with Microsoft fails. The `StaleAuthentication` failure Keyring reports for the confirm says what to add. If you can't change the app registration, set `'freshness' => 'never'`, and users confirm with another method.

> [!WARNING]
> Microsoft's `email` claim is not verified. In an organisation's tenant, it's whatever an administrator typed, and nothing stops a tenant from giving its user someone else's address. Keyring never matches on it anyway, but it also marks every Microsoft identity's address as unverified (`emailVerified` is `false`), unless the token carries the `xms_edov` optional claim set to `true`, meaning the tenant that owns the address's domain has verified it. To get it, add `xms_edov` to the ID token's optional claims under "Token configuration" in the app registration. That only matters if your own code reads the address, as [signing up with a provider](#signing-up-with-a-provider) does.

### GitHub

Create an OAuth app in GitHub's developer settings, and set its "Authorization callback URL" to the callback URL:

```php
'github' => [
    'driver' => 'github',
    'client_id' => env('GITHUB_CLIENT_ID'),
    'client_secret' => env('GITHUB_CLIENT_SECRET'),
],
```

GitHub doesn't speak OpenID Connect, so there's no ID token. Keyring reads who signed in from GitHub's API with the access token instead. The subject is the account's numeric ID, never its login, which can be renamed and taken by someone else.

Keyring asks for the `read:user` and `user:email` scopes. With `user:email`, it keeps the account's primary address, and that address only counts as verified when GitHub says so. Without that scope, it keeps the profile's public address, if there is one, unverified. A GitHub App's user authorization works too, but its tokens carry no scopes, so it gets the public address only.

GitHub can't be asked for a new sign in, and never says when the user last signed in there, so its [`freshness`](#freshness) is `never` by default: a sign in with GitHub never counts toward a [fresh verification](step-up.md#fresh-verification), and the confirm page only offers GitHub links toward a level, never for `keyring.fresh`. `'freshness' => 'reauthenticate'` throws an `InvalidArgumentException` for it. You can opt it into a `round_trip`, which counts a sign in, and a confirm that may let the user straight through on their GitHub session, as fresh. Read [Step-Up](#step-up) before you do.

### Any OpenID Connect Provider

Any provider that publishes an OpenID Connect discovery document works with the `oidc` driver. Give it the provider's issuer, and Keyring finds everything else at `{issuer}/.well-known/openid-configuration`:

```php
'okta' => [
    'driver' => 'oidc',
    'name' => 'Okta',
    'issuer' => 'https://example.okta.com',
    'client_id' => env('OKTA_CLIENT_ID'),
    'client_secret' => env('OKTA_CLIENT_SECRET'),
],
```

The issuer has to be exactly the one the provider's discovery document names, trailing slash included, or Keyring refuses the document. It has to be HTTPS, apart from a provider running on `localhost`, `127.0.0.1`, or `[::1]`, such as Keycloak in Docker while you develop. So does every endpoint the document names. For an issuer anywhere else, Keyring also refuses a token endpoint or key set URL, the endpoints it sends its own requests to, whose host is, or resolves to, an address inside your network: loopback, private, link-local (such as `169.254.169.254`), multicast, or reserved, IPv4 or IPv6, however it's written. A host name with a dot that doesn't resolve is let through, since the request to it fails anyway, and one without a dot isn't. Endpoints on the issuer's own host and port are always allowed, so a Keycloak on your network at `https://keycloak.corp.example` works as it is. For endpoints on another host inside your network, see [`private_endpoints`](#configuration). The authorization endpoint is only where the user's browser goes, so it only has to be HTTPS.

OpenID Connect has a provider send `auth_time` whenever a request has `max_age` (Core, Sec. 3.1.2.1), so its [`freshness`](#freshness) is `reauthenticate` for the `oidc` driver. Keyring asks for `auth_time` with every sign in only when the discovery document says `claims_parameter_supported`, with the `claims` parameter. Without it, nothing asks for `auth_time` on a sign in, though a confirm still gets it from `max_age`. A confirm sends `max_age=0`, `prompt=login`, and the link's address as `login_hint`. A sign in whose ID token has no `auth_time` never counts as recent, and a confirm without one fails. So with a provider that doesn't list `claims_parameter_supported` and leaves `auth_time` out unless it's asked for, no sign in is ever recent: users have to confirm at the provider before their first `keyring.fresh` action. For a provider that doesn't send `auth_time` at all, set `'freshness' => 'never'`, or opt it into a `round_trip` knowing [what that gives away](#step-up).

[More Identity Providers](sso-providers.md) has the config, and the `freshness` to pick, for GitLab, Slack, Twitch, Okta, Auth0, Keycloak, Amazon Cognito, and Salesforce.

## Configuration

These are the defaults:

```php
'sso' => [
    'providers' => [],
    'request_for' => '10m',
    'cache_for' => '1h',
    'store' => null,
],
```

- **`providers`** lists the identity providers, by name. The name is what the routes and the `providers` prop use, so it may only hold letters, digits, `-` and `_`. A provider with any other name throws an `InvalidArgumentException` when it's built. The login page lists them in this order.
- **`request_for`** is how long a user who was sent to a provider has to come back, as a [duration](configuration.md#durations). Each browser keeps up to five of these requests at once, encrypted in its session, and a newer one pushes out the oldest.
- **`cache_for`** is how long each provider's discovery document and signing keys are cached. A token signed with a key Keyring hasn't seen makes it read the keys again, at most once a minute per provider, so a provider can rotate its keys at any time.
- **`store`** is the cache store for them. `null` uses your default store.

Each provider takes these options:

| Option | |
|---|---|
| `driver` | `oidc`, `google`, `microsoft`, `github`, or one you [registered](#custom-drivers). |
| `client_id` | Required. A provider without one throws an `InvalidArgumentException`. |
| `client_secret` | The client's secret. Leave it out for a public client, which sends only its ID. Every request uses PKCE either way. |
| `issuer` | The `oidc` driver's issuer. |
| `tenant` | The `microsoft` driver's tenant. |
| `name` | What the button says: "Sign in with {name}". It defaults to Google, Microsoft or GitHub for those drivers, and to the provider's name in title case otherwise. |
| `scopes` | An array of strings that replaces the driver's scopes. A `null` or empty string in it is left out, so an `env()` can turn one off, and its keys don't matter. OpenID Connect providers always get `openid` as well. Anything else, such as one string of scopes or a number in the array, throws an `InvalidArgumentException`. |
| `parameters` | An array of more to send the user with, such as `['prompt' => 'select_account']` or a `login_hint`. It throws an `InvalidArgumentException` when it isn't an array, or when it sets a parameter Keyring sends itself, such as `state`, `nonce`, `redirect_uri`, or `max_age`. A confirm sends its own `login_hint`, and `prompt=login` where the provider takes it, in place of yours. A `claims` parameter is kept, with `auth_time` added where Keyring asks for it. |
| `freshness` | How much a sign in or a confirm through the provider counts toward a [fresh verification](step-up.md#fresh-verification): `reauthenticate`, `round_trip`, or `never` (or `false`). See [Freshness](#freshness). `reauthenticate` for `oidc` and `microsoft`, `never` for `google`, `github`, and custom drivers built on `OAuth2Provider`. |
| `token_endpoint_auth_method` | `client_secret_basic` sends the secret in an `Authorization` header, `client_secret_post` sends it in the form for a provider that wants it there, and `none` sends no secret, only the client's ID, for a client the provider registered as public. Without it, the secret goes in the header, unless an OpenID Connect provider's discovery lists only `client_secret_post`. A provider without a `client_secret` never sends one. GitHub always takes it in the form. Any other value throws an `InvalidArgumentException`, unless a [custom driver](#custom-drivers) built on `OAuth2Provider` adds it to its `allowedAuthMethods()`. |
| `private_endpoints` | `true` lets an OpenID Connect provider's token endpoint and key set be on a private or local address, which Keyring otherwise only allows on the issuer's own host and port. It's for an issuer you run whose endpoints are on another host inside your network, or whose DNS answers with addresses that look private, such as a service mesh's (Istio's `240.240.0.0/16`) or a proxy's fake IPs (`198.18.0.0/15`). With it, a discovery document that names one of your server's own services gets Keyring's requests sent there, the token endpoint's with the client secret, so only set it for an issuer you trust that far. They still have to be HTTPS. `false` by default, and anything but `true` or `false` throws an `InvalidArgumentException`. |

A provider that can't be built, such as one whose `client_id` comes from an env var that isn't set, or one whose config has a value an option can't take, is left off the login page, and the `InvalidArgumentException` is reported to your exception handler, so the rest of the page and the other providers keep working. It still throws when it's used: its redirect, its callback, or starting a link with it is a `500`. A provider whose name has more than letters, digits, `-` and `_` has no redirect or callback, since the routes don't take such a name, so those are a `404`, and starting a link with it is a `500`. Leave a provider out of the list until its credentials are set.

### Freshness

Signing in with a provider proves the user has a session there, which may be days old: a provider often lets a user who is still signed in there straight through. So a sign in with a provider doesn't always count toward a [fresh verification](step-up.md#fresh-verification) (`keyring.fresh`, which adding a sign-in method, changing the password, and changing the email address need). Each provider's `freshness` says how much it counts:

| `freshness` | A sign in counts as fresh | A confirm |
|---|---|---|
| `reauthenticate` | From when the provider says the user signed in there (`auth_time`). Never, without one. | Asks the provider for a new sign in (`max_age=0`, and `prompt=login` where it's taken, or `prompt=login` alone at Microsoft), and needs an `auth_time` from after the user was sent there. |
| `round_trip` | From when the user comes back, however old their session at the provider is. | A plain round trip to the provider, which counts when the user comes back. |
| `never` (or `false`) | Never. | A plain round trip that counts toward the session's level, as signing in again would, and never as fresh. Only offered toward a level: for `keyring.fresh` the user confirms with another method. |

The defaults are the most secure each provider can give:

| Driver | Default | Can `reauthenticate` |
|---|---|---|
| `oidc` | `reauthenticate` | yes |
| `microsoft` | `reauthenticate`: add the [`auth_time` optional claim](#microsoft), or no sign in is fresh | yes |
| `google` | `never` | only once your app [has session age claims](#google) |
| `github` | `never` | no |
| A custom driver | what its `freshness()` says: `OidcProvider`'s and `OAuth2Provider`'s defaults are those of `oidc` and `github` | if its `supportsReauthentication()` says so |

The `freshness` in the config always wins over the driver's default, whichever driver it is, and `Keyring::sso()->freshness('google')` gives the value that counts. A provider that can't be asked for a new sign in throws an `InvalidArgumentException` for `reauthenticate`, as does a value that isn't one of these.

> [!WARNING]
> `round_trip` lets anyone at a browser that's still signed in to the provider get a fresh verification without typing anything: they sign out of your app and sign in again with the provider, or follow the confirm page's link, and can then add a passkey of their own, change the password, or start an email change. A link from another site can start that confirm too. Only opt a provider into it when that's a risk you accept, such as an identity provider that always asks for a new sign in itself.

A sign in with a `never` provider still signs the user in, at the [assurance level](step-up.md#raising-assurance) it reaches, with the session's timeouts starting then. Only `keyring.fresh` asks for more. See [Step-Up](#step-up), and [Users Whose Only Way In Is Never Fresh](#users-whose-only-way-in-is-never-fresh).

## Login Buttons

The `login` page gets a `providers` prop, a list of the configured providers, each with a `name`, a `label`, and a `url`. The `url` starts a sign in with that provider. Link to it:

```vue
<script setup lang="ts">
import type { LoginProps } from '@keyringjs/keyring'

defineProps<LoginProps>()
</script>

<template>
  <a v-for="provider in providers" :key="provider.name" :href="provider.url">
    Sign in with {{ provider.label }}
  </a>
</template>
```

A plain link works best, since the browser has to leave your site. An Inertia `<Link>` works too, since Keyring answers an Inertia visit with a `409` and an `X-Inertia-Location` header, which Inertia follows with a full page load. Add `?remember=1` to the URL to ask for ["remember me"](devices-and-sessions.md#remember-me). Keyring keeps it in the session for the callback, and ignores a `remember` on the callback itself.

The list is empty until the `SingleSignOn` factor is registered. For a page of your own, such as a registration page, `Keyring::factor('sso')->providers()` gives the same list. `Keyring::sso()->names()` gives just the configured names, without building any provider.

When the provider sends the user back, the sign in goes on as a password sign in would. A user without a second factor is signed in and sent to the page they were going to, or to `home`. A user with one is sent to the challenge page. When it doesn't work, the user is sent back to the login page, with the error on the username field (`email` by default), in the page's `errors`:

- An account nobody linked gets the same "these credentials don't match" message as a wrong password, and so does a user that [`Keyring::allowSignInWhen()`](sign-in-flow.md#who-may-sign-in) or a [risk lock](risk.md#actions) keeps out.
- A provider that couldn't be reached, or a callback that failed a check, gets `keyring::keyring.sso_failed`: "We couldn't sign you in with Google. Please try again."
- A user who said no on the provider's page gets no error. They land on the login page with the `sso-cancelled` status, whose message is in the `status` prop.

## Linking and Unlinking

A user links an account at a provider from your settings page. It's an enrollment, like adding a passkey, so it needs [`Features::manageAuthenticators()`](authenticators.md), a [fresh verification](step-up.md#fresh-verification) (`changes_middleware`), and [a verified address](authenticators.md#who-may-enroll). It also takes the current password, sent as `password`, while the account has an [established](authenticators.md#established-authenticators) password and no established second factor, as [any other sign-in method](authenticators.md#the-password-for-a-first-second-factor) does: a link signs in without the password, so a copy of the session that links an account of its own could otherwise keep signing in after the session ends. Beside an established second factor, a sign in with the link is still asked for it, so the password isn't needed then. The browser package's `linkProvider()` begins the enrollment and sends the browser to the provider:

```vue
<script setup lang="ts">
import { KeyringRequestError, linkProvider, removeAuthenticator } from '@keyringjs/keyring'
import { router } from '@inertiajs/vue3'

async function link(provider: string, password?: string) {
  try {
    await linkProvider(provider, { password })
  } catch (error) {
    if (error instanceof KeyringRequestError && error.status === 423) {
      return router.visit(error.data.redirect)
    }

    throw error
  }
}
</script>
```

Without the package, post the provider's name, and the `password` where it's needed, to `POST /user/authenticators/sso` as JSON. The answer's `enrollment` holds the `provider` and the `url` to send the browser to, which has to be a real navigation (`location.assign(url)`), not a `fetch`:

```json
{
  "status": "enrollment-started",
  "factor": "sso",
  "enrollment": { "provider": "google", "url": "https://accounts.google.com/o/oauth2/v2/auth?..." }
}
```

A provider that isn't configured is a `422` on `provider`. So is one that can't be reached, with `keyring::keyring.sso_failed`. A missing or wrong password is a `422` on `password`, as for any other sign-in method.

Once the user has signed in at the provider, it sends them back to the [callback](#the-callback-url), and Keyring finishes the link there. There's no confirm step: the confirm route can't finish this enrollment. The callback checks again that the user who started the link is still the one signed in, that the address is still verified, and that the verification is still fresh. If it isn't fresh any more, the user confirms first and comes back to the callback, which still works while the request is within [`request_for`](#configuration). Then the user goes back to the page they started from, as with any form:

- `authenticator-added`, flashed with the new authenticator in `Keyring::result('authenticator')`. It's named after the provider and the address, such as "Google (taylor@example.com)", and the security email for a new sign-in method goes out.
- `authenticator-updated` when that account was already linked to this user. Only the address Keyring keeps for it changes, and the provider's name too when the one the link was made with is no longer configured. While its own is, the link keeps it, as it does when it [signs in](#step-up) through another.
- An error on `password` when the link began without the password beside an established second factor that has gone since. The link is spent, so begin it again with the password.
- An error on `provider` when the account is linked to someone else (`keyring::keyring.sso_link_failed`, which doesn't say whose), when the callback failed a check, or when a newer link replaced this one (`keyring::keyring.enrollment_expired`).
- A callback that comes back after `request_for` fails straight away, without asking for a fresh verification first, and goes back to the page the link was started from with `keyring::keyring.enrollment_expired` on `provider`. One whose request this browser doesn't have at all, because it was used already or was never this browser's, fails with `keyring::keyring.sso_failed` on `provider` and goes to `home`, or with a confirm in progress, back to the confirm page with `keyring::keyring.expired` on the username field, as a [confirm](#step-up) is the most likely thing it was. Nothing is logged for either.
- The `sso-cancelled` status, without an error, when the user said no at the provider.

A user may link any number of accounts, at one provider or several. Each one is an authenticator. Its `present()` adds the `provider` and the `email` the provider last gave, so your settings page can list it with the others:

```json
{ "factor": "sso", "id": "01JC6...", "name": "Google (taylor@example.com)", "createdAt": "2026-11-26T09:12:00+00:00", "lastUsedAt": null, "provider": "google", "email": "taylor@example.com" }
```

To show which providers a user may link, pass `Keyring::factor('sso')->providers()` to the page, and use each one's `name` and `label`. The address is brought up to date each time the account signs in, and Keyring never uses it for anything else.

To unlink an account, remove the authenticator with `DELETE /user/authenticators/{authenticator}` (`removeAuthenticator(id)` in the browser package), as you would any other. Removing the user's last way to sign in is refused with `keyring::keyring.last_factor`, so a user whose only way in is one provider has to add another first.

A link counts for the [freeze](authenticators.md#frozen-sign-in-methods) like any other sign-in method. A new one freezes the account for 7 days, so whoever linked it from a copy of the session can't then remove the owner's established methods, and the owner can unlink it whenever they like. Unlinking one the account has had for 7 days is refused while the account is frozen, unless the request [proves an established key](authenticators.md#making-a-change-with-an-established-key). A link can never prove a change itself. Nor does a new link make a policy ask for more: it's one proof of the knowledge category, which an account with a password already has, and on an account without one, only established methods decide what an [`ifEnrolled()`](policies.md#only-when-enrolled) policy asks for. A copy of the session can give such an account its first password, but that password isn't established for 7 days either: it freezes the account, it's never asked for beside the link, and a factor added with it isn't asked for when the owner signs in with the provider, or with the password a later reset gives them.

## How It Fits With the Rest

### Second Factors and Policies

A sign in with a provider is one proof of the knowledge category, the same kind as a password. Keyring doesn't count what the provider did. If the provider asked for a second factor of its own, Keyring still asks for the user's second factor here, as your [policy](policies.md) says. A user with a password and an authenticator app who signs in with Google is asked for the authenticator app, and reaches AAL2 with it.

A link is never asked for as a second step, so it doesn't count as a second factor:

- Linking an account doesn't come with recovery codes, and doesn't keep them. A user who removes their last authenticator app loses their recovery codes, whatever they've linked.
- It never stands in for the established second factor that lets a sign-in method be added [without the password](authenticators.md#the-password-for-a-first-second-factor), and removing the last real second factor beside a link still asks for the password.
- A link is never made the default, and never offered on the challenge page. `PATCH /user/authenticators/{authenticator}` with `default` is refused for one, with an error on `default`, as it is for recovery codes.

The `Identity` behind each sign in has the provider's `amr`, `acr`, and `authTime`, when it sends them. Keyring reads `authTime` for [step-up](#step-up). It never counts `amr` or `acr` toward anything: an `amr` of `mfa` or `hwk` doesn't make the sign in a second factor, phishing resistant, or any more than the one knowledge proof it is. It does keep them, as the provider's claim, on the session's [`Verification`](step-up.md#reading-what-was-proved) for a sign in, a confirm, or a new link, as `providerAmr` and `providerAcr`, so an app that reports how the user signed in, such as an identity provider of its own built on Keyring, can pass them on. Only so much is kept, so a provider can't fill the session: the first 10 distinct `amr` values of 1 to 64 letters, digits, and `.`, `_`, `:`, `/`, or `-`, and an `acr` of 1 to 255 printable ASCII characters with no spaces. Anything else is left out, and an `acr` that doesn't fit is `null`. The whole `Identity`, with the claims the provider sent (a queued listener's without the ID token's `nonce`, `at_hash`, and `c_hash`), comes with the [`ProviderIdentityAccepted`](#hearing-about-accepted-identities) event.

### Hearing About Accepted Identities

`Keyring\Events\ProviderIdentityAccepted` fires each time a provider's account is accepted as one of the user's links. Its `purpose` says what for, as one of the factor's constants:

| `purpose` | When |
|---|---|
| `SingleSignOn::LOGIN` (`login`) | A sign in, once the account the provider vouched for matched a link of a user who may sign in. An account nobody linked, or one whose user the app keeps out, fires nothing. |
| `SingleSignOn::CONFIRM` (`confirm`) | A confirm at the provider brought back the account of the link it was started for. |
| `SingleSignOn::LINK` (`link`) | A new link was added, or a link the user already had was brought up to date. A link refused because someone else linked the account fires nothing. |

It carries the `user`, the link as `authenticator`, the `identity` (`Keyring\Sso\Identity`, with `amr`, `acr`, `authTime`, and the provider's `claims`), and the `purpose`. For a sign in or a confirm it fires when the provider's proof is accepted, before the rest of the pipeline: the user may still be asked for a second factor, or be refused by a risk lock, so it doesn't mean they're signed in. `Authenticated` or `Confirmed` says that. The identity's `request` holds the state, nonce, and PKCE code verifier of a request that's spent, which a listener in the request sees, and a queued listener gets the request with all three blank, and the claims without the ID token's `nonce`, `at_hash`, and `c_hash`.

### Step-Up

A link answers the [confirm page](step-up.md) like any other method, with its `challenge` prop holding the `provider`, its `label`, and the `url` of the `keyring.sso.confirm` route. Send the browser there, or use the browser package's `confirmWithProvider()`. Keyring sends the user to the provider with the link's address as `login_hint`, where it takes one, and the provider sends them back to the [callback](#the-callback-url). It has to bring back the same account at the provider as the link the confirm page offered, for the user who started it, still signed in, and for the confirm still in progress. The callback then confirms through the same pipeline as the confirm page, so rate limits, events such as `Confirmed`, and the security log apply as they do there, and the user goes on to the page that asked them to confirm. A failure goes back to the confirm page with the error on the username field (`email`), as does a callback that comes back after `request_for`, with `keyring::keyring.expired`, even once the confirm itself has run out too: the confirm page then starts a new one for the same page. A user who says no at the provider goes back with the `sso-cancelled` status. A link is only offered while its provider is configured, and while the `keyring.sso.confirm` route is registered.

How much it proves is the provider's [`freshness`](#freshness). When the link's provider and the one a sign in came through differ, because its key was renamed in the config, say, the stricter of the two counts, and a provider that's no longer configured loosens nothing:

- **`reauthenticate`**, the default for any OpenID Connect provider and Microsoft: a sign in counts toward a [fresh verification](step-up.md#fresh-verification) from when the user last signed in at the provider (`auth_time`) rather than from when they came back. Keyring asks for `auth_time` with every sign in where the provider takes the `claims` parameter (Google, and an OpenID Connect provider whose discovery lists `claims_parameter_supported`). Elsewhere nothing asks for it, and the provider may leave it out. Someone at a browser where the user is still signed in there can sign in here, but `keyring.fresh` asks them to confirm all the same. A sign in whose ID token has no `auth_time` never counts as recent, so with a provider that leaves it out, users have to confirm at the provider before their first `keyring.fresh` action. The session itself, its [assurance level](step-up.md#raising-assurance) and its timeouts, still start when they came back. A confirm asks the provider to have the user sign in again whatever session they have (`max_age=0`, and `prompt=login` where the provider takes it), and only counts when the ID token's `auth_time` is no earlier than when the user was sent there, give or take a minute of clock drift, and not in the future. However long they then take at the provider, over its own second factor or a consent screen, doesn't count against them. One without an `auth_time`, or with an older one, is refused with `SsoFailure::StaleAuthentication` and reported, since it means the provider ignored what it was asked, or doesn't send `auth_time`. The message says how to fix it: for Microsoft, the optional claim to add.
- **`never`**, the default for Google, GitHub, and custom drivers built on `OAuth2Provider`: a sign in never counts as recent, whatever `auth_time` it brings, and nor does a confirm. A confirm is a plain round trip to the provider, recorded as proved at an unknown time (`Verification::UNKNOWN`): it counts toward the session's [assurance level](step-up.md#raising-assurance), as signing out and in with the provider again would, and never toward `keyring.fresh`. So the confirm page offers the link toward a level, such as a `keyring:aal2` page after AAL2 lapsed, and not for a fresh verification, where `GET /confirm/sso/redirect` answers `404` for it. There users confirm with their password, a passkey, an authenticator app, or whatever else they have. A user with nothing else is sent to enroll, see [Users Whose Only Way In Is Never Fresh](#users-whose-only-way-in-is-never-fresh).
- **`round_trip`**, only when you set it: Keyring ignores any `auth_time` the provider sends, and both a sign in and a confirm count as recent when the user comes back. The confirm is a plain round trip to the provider, which may let a user who's still signed in there straight through without asking for anything. That's no more than signing out and signing in with the provider again would give, but it means anyone at a browser still signed in to GitHub, say, gets a fresh verification without typing anything. It's a [known limitation](security.md#known-limitations) of opting into it.

Removing a provider from the config, or renaming its key, takes its links off the confirm page. A link still signs in under a renamed key, since it's found by the provider's issuer and subject, and is offered again once it has: a sign in through a provider that's no longer configured moves the link to the key it came through. While the link's own key is still configured, it keeps that key, so a sign in under another key with the same issuer counts for no more than the stricter of the two keys' `freshness`, however many sign ins come through the looser one. But a removed provider's links can't confirm anything. Before you remove a provider, move its users to another method, for example by asking them to set a password.

A confirm builds on what the user already proved, as with any other method. A user who signed in with GitHub, skipped their authenticator app because your [policy](policies.md) let them, and then opens a page behind `keyring:aal2`, is asked for the authenticator app alone. Once AAL2 has lapsed (an hour without a request by default, `sessions.levels.aal2.idle`), nothing counts toward it any more, and the confirm page offers the GitHub link beside the app, so they confirm with both, as signing in again would have them do.

A page behind `keyring.fresh` asks afresh, and only counts what can be proved recently there. The GitHub link can't, so it's left out of what's asked, as well as off the page: a user with a password and an authenticator app confirms with both, and a user with the authenticator app and no password confirms with the app alone, since that's the strongest combination their account can freshly give.

Laravel's `password.confirm` is a freshness check too. A visit to `/confirm` of the user's own, which is where `password.confirm` sends them, only offers what can be proved recently, so the GitHub link isn't offered there either, and a round trip to it never sets `auth.password_confirmed_at`, even when it finishes a confirm toward a level. See [Laravel's Password Confirmation](step-up.md#laravels-password-confirmation).

[`StepUp::unlessMet()`](step-up.md#asking-from-a-controller) with both a level and a moment asks for them in one confirm, when the account can freshly prove the level. The same user, with GitHub and the authenticator app and no password, can't: GitHub never counts as fresh, and the app alone isn't AAL2. So Keyring asks for the two in turn. First the level, with a round trip to GitHub and the app if AAL2 has lapsed, then the fresh verification alone, which the app proved a moment ago, so they're only asked once.

### Users Whose Only Way In Is Never Fresh

A user whose only sign-in method is a link at a `never` provider, such as Google or GitHub by default, or a removed provider, signs in as usual, but can't pass `keyring.fresh`. Adding another sign-in method needs a fresh verification, so they can't add one either. They get the `enroll-first` answer straight away, without a confirm page: `keyring.fresh` sends them to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) with the `enroll-first` status, or answers `403` with it for JSON, since they have nothing to confirm with. A user with a second factor as well, such as an authenticator app, isn't stuck: they confirm with that, as [Step-Up](#step-up) says.

Until they lose it. Without the link, the app is all `keyring.fresh` asks of them, and a recovery code never stands in for the only factor a fresh verification asks for, or one code would be enough to add new sign-in methods. So the confirm page doesn't offer their recovery codes, which still sign them in beside the link. The way out is the same as below: a password reset, which leaves the app and the codes, and the password with a recovery code then makes protected changes, such as removing the lost app.

Their way out is a [password reset](protected-changes.md#resetting-the-password), with `Features::resetPasswords()` on. They sign out, ask for a reset link at `/forgot-password`, and choose a password. The reset unlinks every identity provider, as [below](#password-resets-and-email-changes), so they sign in with the new password, which is fresh, and link the provider again from your settings page. So on your enrollment page, tell a user without a password (`$user->getAuthPassword()` is empty) to sign out and reset it.

Keyring only links a provider for a user who's already signed in with a fresh verification, so this mostly happens to users your own code links, or when you change a provider's `freshness` to `never`. If you [sign people up with a provider](#signing-up-with-a-provider) whose `freshness` is `never`, though, the new account has nothing else. Have them choose a password or add a passkey while the sign up itself still counts as fresh, as the example there does, or opt that provider into a `round_trip`, knowing [what that gives away](#freshness).

### Password Resets and Email Changes

A completed [password reset](protected-changes.md#resetting-the-password) unlinks every identity provider linked to the account. Each link stands in for the password, so one that someone else had linked would let them back in after the owner took the account back. A second factor stays, since a reset only proves the address. Each link removed is logged and announced like any other removal. That happens even while the `SingleSignOn` factor isn't registered, because a link left behind would come back with it. The links are removed before every session is signed out, and once more after, so a sign in with a link that's under way, or a link a signed-out session was adding, doesn't outlast the reset.

An [undone email change](protected-changes.md#reverting) doesn't unlink every provider. Like any other sign-in method, it removes the links added since the change, and leaves the ones the account had before it. The `sso` factor key is Keyring's: a factor of your own with that key would have its authenticators removed by a password reset too.

### Failures and the Security Log

- A failed sign in, such as an account nobody linked, or a callback that failed a check, is logged as `factor_failed` with the `sso` factor and dispatches `FactorFailed`, along with Laravel's `Failed`. The callback has no username field, so `Failed`'s credentials name the user only when one was found, and never take a username from the callback's query string. An account nobody linked counts against the per-IP limit, like a wrong password.
- A user who signed in with a provider and then failed their second factor is logged as `second_factor_failed`, as after a password, and gets the [`second_factor_failed` email](security-log-and-emails.md#email-types). That email names the link they signed in with, rather than saying their password was used.
- A link that's refused is logged as `enrollment_refused` with the reason `invalid`, or `not_allowed` for an unverified address, and dispatches `EnrollmentRefused`.
- A user who said no at the provider isn't logged.
- A sign in logs `signed_in` with the factor `sso`, and adding or removing a link logs `authenticator_added` or `authenticator_removed`.

What went wrong is a `Keyring\Exceptions\SsoFailed`, whose `reason` is a `Keyring\Enums\SsoFailure`, such as `InvalidState` or `InvalidToken`. Its message says which check failed, and never carries a code, a token, or a secret, so it's safe to log. Keyring catches it in its own routes, where the user only sees `sso_failed`, and reports it to your exception handler, so a wrong client secret, a provider that's down, or a server clock that's off shows up in your logs. It doesn't report `Denied` or `InvalidState`, which users cause every day by saying no, going back, or coming back too late. `SsoFailed::expected()` says whether a failure is one of those two, for routes of your own.

## No Sign Up, and No Linking by Email

Keyring never creates an account for someone who signs in with a provider, and never links an account at a provider to a user because they share an address. Some providers let an account carry an address its owner hasn't proven, as Microsoft's tenants do, so linking by address would let someone sign in as whoever has that address in your app. An account nobody linked is answered like a wrong password.

So users register as they do today, with Keyring's [registration](sign-in-flow.md#registration) or your own, and link a provider afterwards. If you want people to sign up with a provider, you can build that yourself.

### Signing Up With a Provider

`Keyring::sso()` sends users to a provider and takes them back from routes of your own. `start()` returns the URL to send the user to, and keeps the request in the session. `complete()` checks the callback and returns the `Keyring\Sso\Identity` the provider vouched for, with its `issuer`, `subject`, `email`, `emailVerified`, `name`, and the `claims` it sent. These routes create the account, link it, and sign the new user in. Someone who already signed up is signed in through Keyring's pipeline instead:

```php
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Keyring\Exceptions\SsoFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\SingleSignOn;
use Keyring\Login\Registration;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;

Route::middleware('guest')->group(function () {
    Route::get('/sign-up/google', fn () => redirect()->away(
        Keyring::sso()->start('google', 'sign-up', route('sign-up.google.callback')),
    ))->name('sign-up.google');

    Route::get('/sign-up/google/callback', function (Request $request) {
        try {
            $identity = Keyring::sso()->complete($request, 'google');
        } catch (SsoFailed) {
            return to_route('register')->withErrors(['email' => 'We couldn\'t sign you up with Google.']);
        }

        abort_unless($identity->request->purpose === 'sign-up', 404);

        try {
            // Someone who already signed up: an ordinary sign in.
            if (Keyring::factor(SingleSignOn::KEY)->linked($identity) !== null) {
                $request->attributes->set(SingleSignOn::IDENTITY, $identity);

                return Keyring::attempt($request, SingleSignOn::KEY);
            }

            $email = $identity->email === null ? null : Keyring::normalizeUsername($identity->email);

            // Google only vouches for who owns a Gmail address, or one in a
            // Google Workspace domain (the "hd" claim). Any other address
            // was verified once, when the Google account was made, and may
            // have changed hands since.
            $vouched = $identity->emailVerified && $email !== null
                && (str_ends_with($email, '@gmail.com') || (is_string($identity->claims['hd'] ?? null) && $identity->claims['hd'] !== ''));

            if (! $vouched || app(Registration::class)->taken($email)) {
                return to_route('register')->withErrors(['email' => 'Sign up with your email address, then link Google from your settings.']);
            }

            [$user, $link] = DB::transaction(function () use ($identity, $email) {
                $user = User::create(['name' => $identity->name ?? $email, 'email' => $email, 'password' => null]);
                $user->forceFill(['email_verified_at' => now()])->save();

                return [$user, $user->authenticators()->create([
                    'factor' => SingleSignOn::KEY,
                    'name' => "Google ({$email})",
                    'credential_id' => SingleSignOn::credentialId($identity->issuer, $identity->subject),
                    'confirmed_at' => now(),
                    'meta' => ['provider' => 'google', 'issuer' => $identity->issuer, 'subject' => $identity->subject, 'email' => $identity->email],
                ])];
            });

            // The account didn't exist until this request, so this sign
            // in counts as fresh: long enough to choose a password or
            // add a passkey.
            app(SignIn::class)->as($request, $user, [Verification::of($link)]);
        } catch (ValidationException $e) {
            return to_route('login')->withErrors($e->errors());
        }

        return redirect('/settings/security');
    })->middleware('throttle:keyring-login-options')->block()->name('sign-up.google.callback');
});
```

A few things to keep from this example:

- The sign-up callback is a second redirect URI, `https://example.com/sign-up/google/callback`, so register it with the provider too. Don't put your own routes under `/auth/{provider}/`, which is Keyring's.
- Only take an address the provider is the authority for. `emailVerified` alone isn't enough: Google [says](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token) it's only authoritative for an `@gmail.com` address, or a Google Workspace account, which has the `hd` claim. Any other address was verified when the Google account was made, and "ownership of the third party email account may have since changed". Without that check, someone who once had `taylor@example.com` and still has a Google account on it could sign up as Taylor, add a passkey while the sign up is fresh, and keep it through Taylor's password reset, which only unlinks identity providers. Everyone else is sent to register with their address, and link Google afterwards.
- Adapting this to another provider, trust only the flag that provider is the authority for. Microsoft's `emailVerified` is rarely `true`, since a tenant can give its users any address, so don't create accounts from it. GitHub's is `true` for a primary address GitHub verified, which, like Google's flag for an outside address, says the address was proved once, not that the account still owns it. When in doubt, refuse, or create the account unverified and send Laravel's verification email before signing anyone in.
- Never take over an account that already has the address. `Registration::taken()` is the check Keyring's own registration makes: it also counts an account your global scopes hide, and an address held for its previous owner while their email change can still be undone.
- Run the address through `Keyring::normalizeUsername()` before you look for it or store it, as Keyring's registration does. A provider may send `Taylor@Example.com` for the account your app has as `taylor@example.com`.
- The user and the link are created in one transaction, so a failure part way doesn't leave an account without its link, with an address nobody can sign up with again.
- The callback has a rate limiter, `keyring-login-options`, the one Keyring's own callback uses for guests, since each call reaches the provider and may create an account.
- The new user has no password, so the `password` column has to be nullable. Google's [`freshness`](#freshness) is `never`, so none of their later sign ins with Google is fresh, and without another method they can't make [protected changes](protected-changes.md), add a passkey, or set a password. So the new account is signed in with `SignIn::as()`, as Keyring's own registration signs in a new user with the password they just chose, and the sign up counts as a fresh verification. That gives away one thing: someone at a browser still signed in to the victim's Google account can create the account here first, and set a password or add a passkey within the window. Anything set then is announced as it is for any account: a passkey or authenticator app with the `authenticator_added` [email](security-log-and-emails.md#email-types), and a password with `password_changed`, both to the address Google vouched for, so its owner hears of it. Send them straight to your settings page to choose a password (`PUT /user/password` asks no current password of an account without one) or add a passkey, within the 15 minutes `keyring.fresh` gives them. Otherwise they're left with [a password reset](#users-whose-only-way-in-is-never-fresh) as the way to get one. Or ask for the password on the sign-up form itself, before you create the account.
- Only a new account is signed in that way. Everyone else goes through `Keyring::attempt()`, which runs the same pipeline as Keyring's own callback, with the identity on the request under `SingleSignOn::IDENTITY`, so their second factor is asked for and their sign in counts as Google's `freshness` says. It answers as the login form does. See [Starting a Sign In Yourself](sign-in-flow.md#starting-a-sign-in-yourself). `SignIn::as()` skips that pipeline, so never call it for an account that already existed.
- The link is stored the way Keyring stores one, with `SingleSignOn::credentialId($issuer, $subject)`, so Keyring's own button signs the same user in afterwards, and a password reset unlinks it.
- The request is started with a purpose of your own, `sign-up`, and the callback checks it. Keyring's callback refuses a request with a purpose it didn't start, so a sign-up can't be finished there.
- If you'd rather a provider's sign ins counted as fresh, you can opt it into a `round_trip`, but read [what that gives away](#freshness) first.

## Frontends Laravel Doesn't Serve

A [headless frontend](headless.md), such as a Nuxt app on `app.example.com`, can offer providers too. A JSON request to the redirect route answers with the provider's URL rather than redirecting, so the frontend can send the browser there itself. The browser package's `signInWithProvider()` does both:

```ts
import { signInWithProvider } from '@keyringjs/keyring'

await signInWithProvider('google', { remember: true })
```

Start the callback URL at the frontend with [`Keyring::linkRootUsing()`](headless.md#emailed-links), as you do for emailed links, and register that URL with the provider. With the `auth` prefix, that's `https://app.example.com/auth/auth/google/callback`. The frontend serves a page at that path, which passes its path and query on to Laravel as JSON, from the browser:

```ts
import { json, routes } from '@keyringjs/keyring'

const answer = await json('GET', routes.ssoCallback('google') + location.search)
```

The answer is the one a sign in gives: `authenticated`, a `202` naming the `challenge` page, a `422` with the error on the username field, or the `sso-cancelled` status with `page: "login"`. For a link, it's `authenticator-added` or `authenticator-updated` with the `authenticator`, a `422` on `provider`, or a `423` when the user's verification is no longer [fresh](step-up.md#fresh-verification). After a `423`, send the user to confirm, and then back to the same callback URL, which still finishes the link within `request_for`. A callback whose request expired is a `422`, never a `423`: on `provider` for a link, and on the username field for a confirm. One whose request is used up or not this browser's is a `422` too, on the username field while a confirm is in progress and on `provider` otherwise. For a [confirm](#step-up), it's `authenticated` with the `redirect` to carry on to, a `422` on the username field (`429` when rate limited), or `sso-cancelled` with `page: "confirm"`. A JSON request to `keyring.sso.confirm` answers with the provider's `url`, as the redirect route does, and an Inertia visit gets a `409` with `X-Inertia-Location`. See [Where Each Answer Goes](headless.md#where-each-answer-goes). The callback's URL holds the provider's code, which is no use without the PKCE verifier in the user's session, but give the page the same headers as the [pages emailed links open](headless.md#the-pages-emailed-links-open) anyway, and keep analytics off it.

## Security Notes

- **Issuer and subject.** An account at a provider is the pair of its issuer and subject, which no other provider can claim. Keyring stores a hash of the two as the link's credential ID, and never looks at the address. A provider that changes its issuer, or a Microsoft user who moves tenant, is a new account to Keyring.
- **The callback is tied to the browser.** The `state` names a request this browser's session started, which can be used once, for the provider it was started with, before `request_for` runs out. Every request carries a PKCE challenge (S256), so a code that leaks from the callback URL is no use to anyone else, and OpenID Connect requests carry a `nonce` that the ID token has to repeat. Keyring makes and checks all of these for you.
- **ID tokens.** Keyring checks every ID token as OpenID Connect Core asks: it's signed by one of the provider's published keys with RS256, PS256, ES256, or EdDSA (never `none` or a shared secret), it's from the configured issuer, for this app (`aud` and `azp`), current, within a minute of clock drift, and has the request's nonce. It checks the signature even though the token came straight from the provider, so a misconfigured endpoint or a TLS proxy in between can't hand over someone else.
- **Mix-up.** A callback that names another issuer in its `iss` parameter (RFC 9207) is refused before its code goes anywhere, and so is one without it from a provider whose discovery says it always sends one. A callback finished at another provider's URL is refused too.
- **Only HTTPS.** Discovery documents, keys, and endpoints have to be HTTPS, apart from `localhost`, `127.0.0.1`, and `[::1]`, where an issuer on one of those may also name plain HTTP endpoints. So that a provider can't point Keyring's own requests at your server's own services, the endpoints Keyring sends them to, the token endpoint (whose request carries the client secret) and the key set, can't be on an inward address either: a private, link-local (such as `169.254.169.254`), multicast, or other non-public IP, any other spelling of the loopback, a name whose DNS records include one, or a name without a dot that doesn't resolve. Each name is looked up once a request. Endpoints on the issuer's own host and port are allowed, since you chose that host and Keyring already read discovery from it, and so are all of an issuer's on this machine. The authorization endpoint is only where the user's browser goes, so it only has to be HTTPS. The check happens when Keyring looks the name up, and the HTTP client looks it up again, so it doesn't stop a provider whose DNS answers change in between. Keyring follows no redirects from a provider, and reads the callback from the query string only.
- **`private_endpoints`.** It turns the inward check off for one provider, for endpoints on another host inside your network, or DNS that answers with private-looking addresses. A provider with it set can have Keyring send requests, with the client secret, to anything your server can reach over HTTPS, so only set it for an issuer you run or trust that far, never for one users or tenants can choose.
- **Cached only once checked.** A discovery document is only cached once it names the configured issuer and HTTPS authorization, token, and key endpoints, and a key set only once it holds at least one key. One that fails is asked for again next time, rather than kept for `cache_for`.
- **RS256.** Google and Microsoft sign their ID tokens with RS256 alone, so Keyring accepts it here, though not for [passkeys](passkeys.md#rs256-and-windows-hello) by default. If you assess against ASVS, note it under 11.6.1. A provider's RSA key has to be at least 2048 bits (`Keyring\Sso\SignedToken::SHORTEST_RSA_KEY`), which is what Google and Microsoft use. It's a floor of its own: raising passkeys' `minimum_rsa_bits` doesn't change it.
- **Brokers.** An Okta, Auth0, Keycloak, or Cognito that sends users on to another provider may stamp a new `auth_time` after a silent round trip there, so `reauthenticate` only means something when users type their credentials at the broker itself. See [Picking a Freshness](sso-providers.md#picking-a-freshness).
- **Cookies.** Keep `SESSION_SAME_SITE` at `lax`: with `strict`, the browser leaves the session cookie off the user's return from the provider, and every callback fails. With the `cookie` session driver, the session itself can't stop an old copy of the cookie bringing a used `state` back, so Keyring also marks each `state` used in the cache store `cache.limiter` names. On more than one server, that store has to be shared, such as Redis or the database, not `file` or `array`.
- **Sessions.** Keyring's session carries on after the provider's session ends, and signing out of one doesn't sign the user out of the other. Keyring reads nothing from the provider after the sign in.
- **Recent sign ins.** By default no sign in with a provider counts toward `keyring.fresh` on the strength of a session the user may have had there for days. With `reauthenticate` (OpenID Connect providers and Microsoft), a sign in counts from the ID token's `auth_time`, not from when the user came back, a sign in without one never counts as recent (and Keyring only asks for it on a sign in where the provider takes the `claims` parameter), and a confirm needs an `auth_time` from after the user was sent to the provider, after asking for `max_age=0` (and `prompt=login` where it's taken). With `never` (Google and GitHub), a sign in never counts, and nor does a confirm, which the confirm page only offers toward a level. Only a provider you opt into a `round_trip` counts from when the user came back, for a sign in and a confirm alike: anyone at a browser still signed in there gets a fresh verification without typing anything. A renamed or removed provider never makes a sign in count for more than the provider it came through says. See [Freshness](#freshness) and [Step-Up](#step-up).

## Custom Drivers

`Keyring::sso()->extend()` registers a driver of your own, or replaces one of Keyring's. The resolver gets the provider's config and its name, and returns a `Keyring\Contracts\IdentityProvider`. Call it in your `KeyringServiceProvider`'s `boot()` method. This one only lets in accounts from one Google Workspace domain:

```php
use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\SsoFailed;
use Keyring\Facades\Keyring;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\Providers\GoogleProvider;

Keyring::sso()->extend('workspace', fn (array $config, string $name) => new class($name, $config) extends GoogleProvider
{
    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        $identity = parent::identityFrom($request, $tokens, $query);

        if (($identity->claims['hd'] ?? null) !== $this->config['domain']) {
            throw SsoFailed::because(SsoFailure::InvalidToken, "[{$this->name}] signed in an account outside the workspace.");
        }

        return $identity;
    }
});
```

```php
'staff' => [
    'driver' => 'workspace',
    'name' => 'Acme Staff',
    'domain' => 'acme.com',
    'parameters' => ['hd' => 'acme.com'],
    'client_id' => env('GOOGLE_CLIENT_ID'),
    'client_secret' => env('GOOGLE_CLIENT_SECRET'),
],
```

For an OAuth 2.0 provider without OpenID Connect, extend `Keyring\Sso\Providers\OAuth2Provider`, as the GitHub driver does. It handles the state, PKCE, the code exchange, and client authentication, and asks you for four methods: `authorizationEndpoint()`, `tokenEndpoint()`, `defaultScopes()`, and `identityFrom()`, which reads who signed in from the tokens, usually from the provider's API with `Metadata::http()->withToken(...)`. Use the account's permanent ID as the subject, never a username or an address, and set `emailVerified` only when the provider says so. [More Identity Providers](sso-providers.md#oauth-20-providers) has complete drivers for Discord, Bitbucket, Facebook, and LinkedIn, and a [checklist](sso-providers.md#writing-your-own) for writing your own. It also says why [Sign in with Apple](sso-providers.md#sign-in-with-apple) isn't supported.

The `IdentityProvider` contract has six methods: `name()`, `label()`, `supportsReauthentication()`, which says whether it can be asked for a new sign in and says when there was one, `freshness()`, which returns the `Keyring\Enums\SsoFreshness` its sign ins and confirms count for unless the config says otherwise, `authorizationUrl()`, which builds the URL from the request's state, nonce, PKCE challenge, `maxAge`, and `loginHint`, and `identify()`, which turns the callback into an `Identity`, with `authTime` when the provider says when the user signed in, or throws `SsoFailed`. A provider whose `name()` isn't its name in the config throws. Return `true` from `supportsReauthentication()` only for a provider that can send `auth_time` and honour a `maxAge` of `0`, and `SsoFreshness::Reauthenticate` from `freshness()` only for one that does: Keyring then counts a sign in from its `authTime`, a missing one as never recent, and refuses a confirm without a new one. Your driver's `freshness()` is only its default: Keyring reads the provider's `freshness` option itself, with `SsoFreshness::configured($config['freshness'] ?? null, $name, $provider->freshness())`, which takes `false` for `never` and throws for a value it doesn't know, so `'freshness' => 'never'` holds for any driver, and a typo is refused. `Keyring::sso()->freshness($name)` gives what counts, and is what Keyring goes by. Keyring refuses to build a provider whose freshness comes out `reauthenticate` without `supportsReauthentication()`. A driver that behaves differently by freshness, as `OidcProvider` asks for `auth_time` with every sign in when it's `reauthenticate`, can read the option itself the same way. `OAuth2Provider` and `OidcProvider` do that, with `defaultFreshness()` for when the config says nothing: `never` for `OAuth2Provider`, which can't be asked for a new sign in, and `reauthenticate` for `OidcProvider`, which can. The Google driver overrides it with `never`. It asks for `auth_time` with the `claims` parameter where `takesClaimsParameter()` says it can, and for a new sign in with `max_age`, and `prompt=login` for a `maxAge` of `0`, from `reauthenticationParameters()`, which you can override as the Google and Microsoft drivers do.

`Keyring::sso()->start()` takes a `maxAge` too, for routes of your own: the user has to have signed in at the provider no more than that many seconds before they were sent there (the request's `createdAt`), and `complete()` refuses an identity whose `authTime` is missing or older, give or take a minute, or in the future, with `SsoFailure::StaleAuthentication`. Asking a provider that can't be asked (`supportsReauthentication()` is `false`) throws an `InvalidArgumentException`. Any other may be asked, whatever its `freshness`, and an OpenID Connect provider is then asked for `auth_time` with the `claims` parameter where it takes one. Its `loginHint` is sent as `login_hint` to an OpenID Connect provider.

## Testing

`Keyring\Testing\FakeIdentityProvider` stands in for a provider. It answers Keyring's requests through `Http::fake()` as the real one would: discovery, signing keys, the token endpoint, and GitHub's API. Its ID tokens are really signed, so every check Keyring makes runs in your test. `register()` adds it to `sso.providers`, and the `sso()` factory state links an account to a user:

```php
use Keyring\Enums\Assurance;
use Keyring\Models\Authenticator;
use Keyring\Sso\Providers\GoogleProvider;
use Keyring\Testing\FakeIdentityProvider;

it('signs in with Google', function () {
    $google = FakeIdentityProvider::google()->register('google');
    $user = User::factory()->create();
    Authenticator::factory()->sso('google', subject: '42', issuer: GoogleProvider::ISSUER)->for($user, 'authenticatable')->create();

    $url = $this->get(route('keyring.sso.redirect', 'google'))->headers->get('Location');

    $this->get($google->signIn(['sub' => '42'])->approve($url))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
});

it('links a Google account', function () {
    $google = FakeIdentityProvider::google()->register('google');
    $user = User::factory()->create();

    $url = $this->actingAs($user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'google', 'password' => 'password'])
        ->json('enrollment.url');

    $this->get($google->approve($url))->assertSessionHas('status', 'authenticator-added');
});
```

| Method | |
|---|---|
| `new FakeIdentityProvider()`, `::google()`, `::microsoft($tenant = 'common')`, `::github()` | A provider for that driver. The plain one is an OpenID Connect provider at `https://idp.test`, whose default user matches the `sso()` factory state's defaults. |
| `register($name = 'fake', $config = [])` | Adds it to `sso.providers` with its client's credentials, and anything in `$config`. |
| `signIn($user, $emails = null)` | Who signs in next: ID token claims, or GitHub's user and its addresses. |
| `approve($url)` | The callback URL for a user who signed in at the authorization URL Keyring sent them to. It checks that URL the way the provider would. |
| `deny($url, $error = 'access_denied')` | The callback URL for a user who said no, or for another error. |
| `signedInAt($at)` | The user already has a session at the provider from then, and is let straight through on it, with that `auth_time`, until a request asks for a new sign in (`prompt=login`, or a `max_age` it's past). Without it, they sign in at the first `approve()`. |
| `ignoringReauthentication()` | Keeps letting the user through on that session even when a request asks for a new sign in, as a provider that ignores `prompt=login` would. |
| `withAuthTimeClaim()` | The fake Microsoft sends `auth_time`, as Microsoft does once the app registration adds the [optional claim](#microsoft). Without it, like Microsoft, it leaves `auth_time` out. The fake Google, like Google, only sends `auth_time` when the request's `claims` parameter asks for it. |
| `withKeyIssuer($issuer)` | The `issuer` its keys name. The fake Microsoft's name `https://login.microsoftonline.com/{tenantid}/v2.0`, as Microsoft's do, and the others' name none. With another tenant's issuer, a multi-tenant Microsoft provider refuses the tokens they sign. `null` names none. |
| `withClaims()`, `expired()`, `unsigned()`, `signedWithUnpublishedKey()`, `rotateKeys()`, `failExchange()`, `down()` | Tokens and answers Keyring should refuse, for testing your error pages. `withClaims(['auth_time' => null])` leaves `auth_time` out. |

Keyring refuses a token endpoint or key set a provider elsewhere names when its host resolves inside your network, so it looks host names up with `Keyring\Sso\HostResolver`. Making a `FakeIdentityProvider` swaps that for `HostResolver::fake()`, unless your test already did, so no test asks your DNS about `idp.test` or a real provider's hosts. For a test of your own without the fake, call `HostResolver::fake()` yourself, with the addresses a name should resolve to: `HostResolver::fake(['idp.example.com' => ['10.0.0.5']])`. A name that isn't listed resolves to nothing, which Keyring lets through when it has a dot.

To test a confirm with a provider, follow the confirm page's `challenge.url`. Google's `freshness` is `never` by default, so the confirm page doesn't offer it for `keyring.fresh`. Register it with `['freshness' => 'reauthenticate']`, as an app with session age claims would, to test asking for a new sign in, or with `['freshness' => 'round_trip']` to test a plain round trip:

```php
it('confirms with Google', function () {
    $google = FakeIdentityProvider::google()->register('google', ['freshness' => 'reauthenticate']);
    $user = User::factory()->create(['password' => null]);
    Authenticator::factory()->sso('google', subject: '42', issuer: GoogleProvider::ISSUER)->for($user, 'authenticatable')->create();

    $this->actingAs($user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);

    $page = $this->getJson(route('keyring.confirm.challenge'))->json('props.challenge.url');
    $url = $this->get($page)->headers->get('Location');

    $this->get($google->signIn(['sub' => '42'])->approve($url))->assertRedirect();
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
});
```

Make it before any catch-all `Http::fake()` of your own, which would otherwise answer its requests first.

Keyring registers its `/auth` routes as the app boots, and only when `sso.providers` lists a provider by then. `register()` changes the config later, so keep the provider in `config/keyring.php` too, as your app does anyway. Its credentials may be empty while testing, since `register()` replaces them, and a provider without its `client_id` is only [left off the login page](#configuration) until then.

## Migrating From the Socialite Recipe

Earlier versions of these docs had a recipe that signed in with GitHub through Socialite, a factor of your own, and a `github_id` column. The `SingleSignOn` factor replaces all of it. To move over:

1. Add the `github` provider to `sso.providers`, and register `SingleSignOn` in place of your `GitHub` factor.
2. Remove the recipe's routes. Keyring's callback for a provider named `github` is `/auth/github/callback`, the path the recipe used for its own, so the two would collide. Your GitHub OAuth app's callback URL can stay as it is. The recipe's separate linking callback, `/settings/github/callback`, isn't needed any more.
3. Move each `github_id` into a link, in a migration:

```php
use App\Models\User;
use Keyring\Factors\SingleSignOn;
use Keyring\Sso\Providers\GitHubProvider;

User::query()->whereNotNull('github_id')->eachById(function (User $user) {
    $subject = (string) $user->github_id;

    $user->authenticators()->firstOrCreate(
        ['factor' => SingleSignOn::KEY, 'credential_id' => SingleSignOn::credentialId(GitHubProvider::ISSUER, $subject)],
        ['name' => 'GitHub', 'confirmed_at' => now(), 'meta' => ['provider' => 'github', 'issuer' => GitHubProvider::ISSUER, 'subject' => $subject, 'email' => null]],
    );
});
```

The provider name, `github` here, has to be the one in `sso.providers`. The address fills in the next time each user signs in.

Each link is dated when the migration runs. An undone email change removes the sign-in methods added since the change, so undoing a change made before the migration removes the link too, as the recipe's listener cleared `github_id`. The user links GitHub again afterwards. Don't backdate `created_at` to get around it: a link someone else added after taking the account would then survive the undo.

4. Remove the listener that cleared `github_id` on `PasswordReset` and `EmailChangeReverted`. Keyring now unlinks every provider on a reset, and an undone email change removes the links added since the change, as above. Then drop the column.
5. Replace `Socialite::fake()` in your tests with [`FakeIdentityProvider::github()`](#testing).
