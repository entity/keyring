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
- [Messages and Translations](#messages-and-translations)
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
```

`home` is where users go after signing in or confirming, when there's no intended URL. It's also used after email verification (with `?verified=1` added) and after confirming an email change while signed in.

Signed-out users are sent to the route named `login`.

## Routes

```php
'routes' => true,

'prefix' => '',

'domain' => null,

'middleware' => ['web'],
```

Keyring registers its routes inside a group with this prefix, domain and middleware. It always adds a middleware that sends `Cache-Control: no-store, private` on every Keyring response.

If you set `routes` to `false`, Keyring registers nothing, and you call `Keyring::routes()` where you want them, for example inside your own group:

```php
Route::prefix('account')->middleware('throttle:60,1')->group(fn () => Keyring::routes());
```

`Keyring::routes()` adds the `middleware` option and the no-cache middleware, but not `prefix` or `domain`; your group decides those. To change the routes themselves, copy `vendor/entity/keyring/routes/keyring.php` into your app instead, and keep the route names: Keyring's controllers, emails and middleware link to routes by name (for example `login`, `keyring.confirm.challenge` and `keyring.devices.report`).

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
'manage_middleware' => ['keyring.fresh:15m'],
```

Extra middleware for adding, renaming and removing authenticators, revoking devices, changing the password and starting an email change. It's applied on top of `auth:{guard}`, which every signed-in Keyring route already has, so don't add `auth` here. By default these routes need a verification in the last 15 minutes. See [Step-Up](step-up.md#fresh-verification).

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
    'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected'],
],
```

`keep_for` is how long entries are kept before [`keyring:prune`](devices-and-sessions.md#pruning) deletes them. `alerts` lists the entry types shown once as ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts) at the next sign in. See [Security Log & Emails](security-log-and-emails.md). Turning the log off also turns off "was this you?" alerts and the `RepeatedFactorFailures` risk signal, since both read from it.

## Security Emails

```php
'notifications' => [],
```

The security emails to send. `Keyring::notify()` in your provider overrides this. See [Security Emails](security-log-and-emails.md#security-emails).

## Pending Logins, Timebox and Rate Limits

```php
'pending_login_ttl' => '10m',

'timebox' => 250_000,

'limits' => [
    'per_account' => 5,
    'per_ip' => 20,
],
```

`pending_login_ttl` is how long a half-finished login or confirmation stays valid, as a [duration](#durations). It's also the `expiresAt` shown on the challenge page.

`timebox` is the minimum time, in microseconds, that a failed factor check takes, so timing doesn't reveal whether an account exists. Successful checks return straight away.

`limits` are the default attempts per minute for each factor, per account and per IP address. See [Rate Limiting](security.md#rate-limiting).

Keyring's form routes (registration, password reset, enrollment confirmation, email changes, verification emails and the emailed links) use a named rate limiter, `keyring`, which allows 6 requests a minute per user, or per IP address for guests. Define your own `keyring` limiter in a service provider's `boot()` method to change it:

```php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(10)->by($request->user()?->id ?: $request->ip()));
```

## Messages and Translations

Keyring's text lives in three translation files under the `keyring::` namespace:

| File | Holds |
|---|---|
| `lang/en/keyring.php` | Validation and error messages, such as `keyring::keyring.invalid`. |
| `lang/en/status.php` | The message for each status slug, such as `keyring::status.password-updated`. See [Status Responses](sign-in-flow.md#status-responses). |
| `lang/en/notifications.php` | The copy for every email Keyring sends. See [Customising the Copy](security-log-and-emails.md#customising-the-copy). |

Publish them to change the wording or add languages:

```bash
php artisan vendor:publish --tag=keyring-lang
```

## The Keyring Facade

`Keyring\Facades\Keyring` is the entry point for everything you set in code:

| Method | Does |
|---|---|
| `Keyring::factors([...])` | Sets the factors users can use. See [Factors](factors.md). |
| `Keyring::extend($key, $resolver)` | Adds one more factor from a closure. Its `key()` must match `$key`. |
| `Keyring::require($requirement)` | Sets the policy. See [Policies](policies.md). |
| `Keyring::pipeline($callback)` | Changes the verification steps. See [The Pipeline](sign-in-flow.md#the-verification-pipeline). |
| `Keyring::respondWith($contract, $implementation)` | Swaps a response. See [Responses](sign-in-flow.md#responses). |
| `Keyring::page($name, $component)` | Changes the component a page renders. See [Pages](sign-in-flow.md#pages). |
| `Keyring::risk([...])->respond(...)` | Configures risk signals and actions. `Keyring::risk()->push(...)` adds signals to the defaults. See [Risk](risk.md). |
| `Keyring::notify([...])` | Turns security emails on. Unknown types throw an `InvalidArgumentException`. See [Security Emails](security-log-and-emails.md#security-emails). |
| `Keyring::passwordRulesUsing($callback)` | Adjusts the password rule. See [Password Rules](protected-changes.md#password-rules). |
| `Keyring::createUsersUsing($action)` | Sets the registration action. |
| `Keyring::routes()` | Registers Keyring's routes yourself, when `routes` is `false`. See [Routes](#routes). |
| `Keyring::useAuthenticatorModel($model)` | Uses your own subclass of `Keyring\Models\Authenticator`. |
| `Keyring::useDeviceModel($model)` | Uses your own subclass of `Keyring\Models\Device`. See [Your Own Device Model](devices-and-sessions.md#your-own-device-model). |
| `Keyring::withoutProtection($callback, reason: ...)` | Changes protected attributes outside Keyring's flows. See [Protected Changes](protected-changes.md#bypassing-protection). |
| `Keyring::activity($user, $limit = 25)` | Recent security log entries. |
| `Keyring::for($user)` | The user's keyring, the same as `$user->keyring`. |
| `Keyring::user()` | The user signed in to Keyring's guard. Throws an `AuthenticationException` when there isn't one. |
| `Keyring::fake()` | Passes or fails factors in tests. See [Testing](testing.md). |
