# Configuration

- [Introduction](#introduction)
- [Durations](#durations)
- [Guard and Users](#guard-and-users)
- [Features](#features)
- [Redirects](#redirects)
- [Routes](#routes)
- [WebAuthn](#webauthn)
- [Managing Authenticators](#managing-authenticators)
- [Devices](#devices)
- [Sessions](#sessions)
- [Protected Attributes and Email Changes](#protected-attributes-and-email-changes)
- [Passwords](#passwords)
- [Risk](#risk)
- [Security Log](#security-log)
- [Security Emails](#security-emails)
- [Pending Logins, Timebox and Rate Limits](#pending-logins-timebox-and-rate-limits)
- [The Keyring Facade](#the-keyring-facade)

## Introduction

Keyring is configured in two places:

- `config/keyring.php` holds values: timeouts, limits, route options.
- `app/Providers/KeyringServiceProvider.php` holds behaviour: which factors exist, the policy, risk responses, swapped responses and pages. These calls go in the provider's `boot()` method.

## Durations

Options that take a duration accept a number of seconds or a string such as `"30s"`, `"15m"`, `"12h"` or `"7d"`. Anything else throws an `InvalidArgumentException`.

## Guard and Users

```php
'guard' => 'web',

'username' => 'email',
```

`guard` is the stateful guard users are signed into. Keyring stores pending logins, step-up state and enrollments in the session, so it needs a session-based guard.

`username` is the user attribute typed at login. It's also the attribute the [email change flow](protected-changes.md#changing-the-email-address) changes, and the field name the login form and password reset forms post. Keyring lowercases what users type before looking them up, so store this attribute lowercased.

## Features

```php
'features' => [
    'registration' => true,
    'password_reset' => true,
    'email_verification' => true,
],
```

Set any of these to `false` to drop their routes. Sign in, challenges, step-up, managing authenticators, devices and protected changes are always on.

## Redirects

```php
'home' => '/dashboard',

'login_redirect' => '/login',
```

`home` is where users go after signing in or confirming, when there's no intended URL. It's also used after email verification (with `?verified=1` added) and after confirming an email change while signed in.

`login_redirect` isn't read by Keyring yet. Signed-out users are sent to the route named `login`.

## Routes

```php
'routes' => true,

'prefix' => '',

'domain' => null,

'middleware' => ['web'],
```

Keyring registers its routes inside a group with this prefix, domain and middleware. It always adds a middleware that sends `Cache-Control: no-store, private` on every Keyring response.

If you set `routes` to `false`, Keyring registers nothing, and you need to define the routes yourself. Keyring has no helper for this. Copy `vendor/entity/keyring/routes/keyring.php` into your app as a starting point, and keep the route names: Keyring's controllers, emails and middleware link to routes by name (for example `login`, `keyring.confirm.challenge` and `keyring.devices.report`).

The browser package uses Keyring's default paths. If you change the prefix, tell it with [`configureRoutes()`](frontend.md#changing-routes). The published pages also contain a few hard-coded paths such as `/login` and `/register`.

## WebAuthn

```php
'webauthn' => [
    'relying_party' => [
        'id' => env('KEYRING_WEBAUTHN_RP_ID'),
        'name' => env('KEYRING_WEBAUTHN_RP_NAME'),
    ],
    'origins' => [],
    'timeout' => 60_000,
],
```

See [Passkeys & Security Keys](passkeys.md#relying-party-and-origins). `timeout` is in milliseconds.

## Managing Authenticators

```php
'manage_middleware' => ['auth', 'keyring.fresh:15m'],
```

The middleware for adding, renaming and removing authenticators, revoking devices, changing the password and starting an email change. By default these need a verification in the last 15 minutes. See [Step-Up](step-up.md#fresh-verification).

## Devices

```php
'devices' => [
    'cookie' => 'keyring_device',
    'trust_for' => '30d',
    'locator' => NullLocator::class,
],
```

`cookie` is the name of the device cookie. `trust_for` is how long "don't ask again on this device" lasts; set it to `null` to hide that option. `locator` is the class that works out a request's location. See [Devices & Sessions](devices-and-sessions.md).

## Sessions

```php
'sessions' => [
    'driver' => env('KEYRING_SESSION_DRIVER', 'database'),
    'connection' => null,
    'table' => 'keyring_sessions',
    'store' => null,
    'idle' => null,
    'absolute' => '30d',
    'levels' => [],
    'middleware' => true,
],
```

| Key | Means |
|---|---|
| `driver` | `database`, `cache`, or the name of a driver you've added. |
| `connection`, `table` | Used by the `database` driver. |
| `store` | The cache store used by the `cache` driver. `null` is your default store. |
| `idle` | Inactivity allowed before a session ends. `null` leaves it to Laravel's session lifetime. |
| `absolute` | The longest a session can last, however active it is. |
| `levels` | Per-assurance overrides for `idle` and `absolute`, keyed `none`, `aal1`, `aal2` or `aal3`. |
| `middleware` | Whether Keyring adds its session middleware to the `web` group for you. |

See [Devices & Sessions](devices-and-sessions.md#the-session-registry).

## Protected Attributes and Email Changes

```php
'protected' => ['email', 'password'],

'email_changes' => [
    'expire' => '24h',
    'revertable_for' => '7d',
],
```

See [Protected Changes](protected-changes.md).

## Passwords

```php
'passwords' => [
    'min_with_mfa' => 8,
    'min_without_mfa' => 15,
    'max' => 128,
    'uncompromised' => true,
    'broker' => null,
],
```

See [Password Rules](protected-changes.md#password-rules). `broker` is the password broker used for resets; `null` is your default broker.

`uncompromised` checks new passwords against a public breach list over the network. You'll usually turn it off in your test environment.

## Risk

```php
'risk' => [
    'levels' => ['medium' => 30, 'high' => 60, 'critical' => 90],
    'recent_change' => '7d',
    'store' => null,
],
```

`levels` are the score thresholds. `recent_change` is how long after an email change the `RecentlyChangedRecovery` signal fires. `store` is the cache store for risk locks. See [Risk](risk.md).

## Security Log

```php
'events' => [
    'enabled' => true,
    'keep_for' => '180d',
],
```

See [Security Log & Emails](security-log-and-emails.md). Turning the log off also turns off "was this you?" alerts and the `RepeatedFactorFailures` risk signal, since both read from it.

## Security Emails

```php
'notifications' => [],
```

The security emails to send. `Keyring::notify()` in your provider overrides this. See [Security Emails](security-log-and-emails.md#security-emails).

## Pending Logins, Timebox and Rate Limits

```php
'pending_login_ttl' => 600,

'timebox' => 250_000,

'limits' => [
    'per_account' => 5,
    'per_ip' => 20,
],
```

`pending_login_ttl` is how many seconds a half-finished login or confirmation stays valid. It's also the `expiresAt` shown on the challenge page.

`timebox` is the minimum time, in microseconds, that a failed factor check takes, so timing doesn't reveal whether an account exists. Successful checks return straight away.

`limits` are the default attempts per minute for each factor, per account and per IP address. See [Rate Limiting](security.md#rate-limiting).

## The Keyring Facade

`Keyring\Facades\Keyring` is the entry point for everything you set in code:

| Method | Does |
|---|---|
| `Keyring::factors([...])` | Sets the factors users can use. See [Factors](factors.md). |
| `Keyring::extend($key, $resolver)` | Adds one more factor from a closure. |
| `Keyring::require($requirement)` | Sets the policy. See [Policies](policies.md). |
| `Keyring::pipeline($callback)` | Changes the verification steps. See [The Pipeline](sign-in-flow.md#the-verification-pipeline). |
| `Keyring::respondWith($contract, $implementation)` | Swaps a response. See [Responses](sign-in-flow.md#responses). |
| `Keyring::page($name, $component)` | Changes the component a page renders. See [Pages](sign-in-flow.md#pages). |
| `Keyring::risk([...])->respond(...)` | Configures risk signals and actions. See [Risk](risk.md). |
| `Keyring::notify([...])` | Turns security emails on. See [Security Emails](security-log-and-emails.md#security-emails). |
| `Keyring::createUsersUsing($action)` | Sets the registration action. |
| `Keyring::useAuthenticatorModel($model)` | Uses your own subclass of `Keyring\Models\Authenticator`. |
| `Keyring::withoutProtection($callback, reason: ...)` | Changes protected attributes outside Keyring's flows. See [Protected Changes](protected-changes.md#bypassing-protection). |
| `Keyring::activity($user, $limit = 25)` | Recent security log entries. |
| `Keyring::for($user)` | The user's keyring, the same as `$user->keyring`. |
| `Keyring::fake()` | Passes or fails factors in tests. See [Testing](testing.md). |
