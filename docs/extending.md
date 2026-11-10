# Extending Keyring

- [Introduction](#introduction)
- [What You Can Change](#what-you-can-change)
- [Replacing a Controller or Service](#replacing-a-controller-or-service)
- [Changing the Routes](#changing-the-routes)
- [What Stays Fixed](#what-stays-fixed)

## Introduction

Keyring works after `keyring:install` and a migration, and nearly everything it does from there is yours to change. The code an app is expected to own is published into it: the config, the migrations, a service provider, the [actions](protected-changes.md) and the [notifications](security-log-and-emails.md#security-emails). The rest stays in the package, where it keeps getting fixes, behind options and hooks.

This page lists them all, with where each is explained. [Recipes](recipes.md) has worked examples of the common ones.

## What You Can Change

| To change | Use | See |
|---|---|---|
| Which features are on | The `features` list | [Adding Features](quick-start.md#adding-features) |
| Any number, lifetime or limit | `config/keyring.php` | [Configuration](configuration.md) |
| How users sign in | `Keyring::factors()`, `Keyring::extend()`, your own `Factor` | [Factors](factors.md) |
| What they must prove | `Keyring::require()` | [Policies](policies.md) |
| The steps a verification runs | `Keyring::pipeline()` | [The Pipeline](sign-in-flow.md#the-verification-pipeline) |
| Signing in from a route of your own, like a social login's callback | `Keyring::attempt()` and a factor that can start a login | [Social Login With Socialite](recipes.md#social-login-with-socialite) |
| How a user is found, and how usernames are normalised | `Keyring::findUsersUsing()`, `Keyring::normalizeUsernamesUsing()` | [Finding the User](sign-in-flow.md#finding-the-user) |
| The attribute users sign in with, and the one holding their address | `username` and `email` | [Guard and Users](configuration.md#guard-and-users) |
| Creating users, resetting and changing passwords, validating a new address | The published actions in `app/Actions/Keyring` | [Protected Changes](protected-changes.md) |
| Every email: wording, template, channel, or whether it's sent | The published notifications in `app/Notifications/Keyring` and `Keyring::notifications()` | [Security Emails](security-log-and-emails.md#security-emails) |
| What a page renders | `Keyring::page()` | [Pages](sign-in-flow.md#pages) |
| What Keyring answers with | `Keyring::respondWith()` and the contracts in `Keyring\Contracts\Responses` | [Responses](sign-in-flow.md#responses) |
| Validation and status messages | The `keyring-lang` translation files | [Messages and Translations](configuration.md#messages-and-translations) |
| The route prefix, domain and middleware | `prefix`, `domain` and `middleware` | [Routes](configuration.md#routes) |
| The middleware on account changes | `changes_middleware` | [Account Changes and Enrollment](configuration.md#account-changes-and-enrollment) |
| The form rate limits | The `keyring` and `keyring-login-options` rate limiters | [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits) |
| Who may add a sign-in method | `Keyring::allowEnrollmentWhen()` | [Who May Enroll](authenticators.md#who-may-enroll) |
| Whether registering signs the user in | `Keyring::signInAfterRegistering()` | [Registration](sign-in-flow.md#registration) |
| Risk signals and what they do | `Keyring::risk()`, your own `Signal` | [Risk](risk.md) |
| Where a request is located | `devices.locator`, your own `LocatesIps` | [Devices & Sessions](devices-and-sessions.md) |
| How a browser is described | `Keyring::describeDevicesUsing()` | [Devices & Sessions](devices-and-sessions.md) |
| Where sessions are registered | `sessions.driver`, your own `SessionRegistry` | [The Session Registry](devices-and-sessions.md#the-session-registry) |
| Whether Keyring checks sessions on the `web` group | `sessions.middleware` | [The Session Middleware](devices-and-sessions.md#the-session-middleware) |
| What's stored as an IP address | `Keyring::recordIpsUsing()` | [What's Stored](security-log-and-emails.md#whats-stored) |
| Where emailed links start | `Keyring::linkRootUsing()` | [Emailed Links](security.md#emailed-links) |
| The models | `Keyring::useAuthenticatorModel()` and the other three | [The Keyring Facade](configuration.md#the-keyring-facade) |
| Which attributes are protected | `protected`, `Keyring::withoutProtection()` | [Protected Changes](protected-changes.md) |

Risk signals, security notices, the security log, devices and every sign-in method but the password are off until you turn them on.

## Replacing a Controller or Service

Keyring's controllers and services are resolved from the container, so binding your own class in a service provider's `register()` method swaps one. Extend Keyring's and override what you need:

```php
use App\Http\Controllers\AuthenticatorController;
use Keyring\Http\Controllers\AuthenticatorController as KeyringAuthenticatorController;

$this->app->bind(KeyringAuthenticatorController::class, AuthenticatorController::class);
```

The services behind them work the same way: `Keyring\Login\SignIn`, `Keyring\Login\StepUp`, `Keyring\Changes\AuthenticatorChanges`, `EmailChanges` and `PasswordChanges`, `Keyring\Devices\DeviceManager`, `Keyring\Support\Throttle` and `Keyring\WebAuthn\Ceremonies`. Their methods are public or protected, never private.

This is the last resort. A class you've replaced stops getting Keyring's fixes for whatever you overrode, so prefer an option or hook above when one does the job, and call the parent for the rest.

## Changing the Routes

Set `routes` to `false` and call `Keyring::routes()` inside your own group to change the prefix or middleware. To change a route itself, copy `vendor/entity/keyring/routes/keyring.php` into your app and load that instead. Keep the route names: Keyring's controllers, responses and emailed links find routes by name. See [Routes](configuration.md#routes).

## What Stays Fixed

A few things have no switch, because turning them off would quietly remove a protection:

- Plain `EmailCode::class` is refused. `EmailCode::asSecondFactor()` is the switch, and it says what you're accepting.
- A user can't remove their last way to sign in, and removing the last second factor takes the password, typed again and long enough to stand alone.
- An email change is confirmed from the new address, announced to the old one, and can be undone from there.
- Trusting a device takes a real second factor, and the confirm page never accepts recovery codes.
- The steps that check rate limits, the policy and risk can't be dropped from the pipeline by accident. `dangerouslyReplace()` is there when you mean it.
- Emailed links are never built from the request's `Host` header.

Keyring also needs Eloquent user models with the `HasKeyring` trait and a session guard. It doesn't sign users in to token guards.

The field names forms post (`remember`, `trust`, `code`, `credential`, `authenticator`), the route names and the status slugs are fixed too, since the [browser package](frontend.md) and your pages rely on them.
