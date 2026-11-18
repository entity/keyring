# Extending Keyring

- [Introduction](#introduction)
- [What You Can Change](#what-you-can-change)
- [Replacing a Controller or Service](#replacing-a-controller-or-service)
- [Changing the Routes](#changing-the-routes)
- [What Stays Fixed](#what-stays-fixed)

## Introduction

Once you've run `keyring:install` and a migration, Keyring works. From there, nearly everything it does is yours to change. The code that an app is expected to own is published into your app. That includes the config, the migrations, a service provider, the [actions](protected-changes.md), and the [notifications](security-log-and-emails.md#security-emails). The rest stays in the package, where it keeps receiving fixes. You change it through options and hooks.

This page lists all of them, along with where each one is explained. The [Recipes](recipes.md) page has worked examples of the most common ones.

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
| Every email: wording, template, channel, or whether it's sent | `Keyring::notifications()`, with your own class for a type or `null`, and `SecurityNotice::toMailUsing()` | [Security Emails](security-log-and-emails.md#security-emails) |
| What a page renders | `Keyring::page()` | [Pages](sign-in-flow.md#pages) |
| What Keyring answers with | `Keyring::respondWith()` and the contracts in `Keyring\Contracts\Responses` | [Responses](sign-in-flow.md#responses) |
| Validation and status messages | The `keyring-lang` translation files | [Messages and Translations](configuration.md#messages-and-translations) |
| The route prefix, domain and middleware | `prefix`, `domain` and `middleware` | [Routes](configuration.md#routes) |
| The middleware on account changes | `changes_middleware` | [Account Changes and Enrollment](configuration.md#account-changes-and-enrollment) |
| The form rate limits | The `keyring`, `keyring-pages` and `keyring-login-options` rate limiters | [Rate Limits](configuration.md#pending-logins-timebox-and-rate-limits) |
| Who may sign in at all | `Keyring::allowSignInWhen()` | [Who May Sign In](sign-in-flow.md#who-may-sign-in) |
| Who may add a sign-in method | `Keyring::allowEnrollmentWhen()` | [Who May Enroll](authenticators.md#who-may-enroll) |
| Whether registration says when an address is taken | `registration.reveal_taken` | [Registration](sign-in-flow.md#registration) |
| Whether registering signs the user in, when it says so | `Keyring::signInAfterRegistering()` | [Saying When an Address Is Taken](sign-in-flow.md#saying-when-an-address-is-taken) |
| Risk signals and what they do | `Keyring::risk()`, your own `Signal` | [Risk](risk.md) |
| Where a request is located | `devices.locator`, your own `LocatesIps` | [Devices & Sessions](devices-and-sessions.md) |
| Whose key attestation is trusted | `webauthn.attestation_roots`, your own `TrustsAuthenticators` | [Passkeys & Security Keys](passkeys.md#trusting-each-model-separately) |
| How a browser is described | `Keyring::describeDevicesUsing()` | [Devices & Sessions](devices-and-sessions.md) |
| Where sessions are registered | `sessions.driver`, your own `SessionRegistry` | [The Session Registry](devices-and-sessions.md#the-session-registry) |
| Whether Keyring checks sessions on the `web` group | `sessions.middleware` | [The Session Middleware](devices-and-sessions.md#the-session-middleware) |
| What's stored as an IP address | `Keyring::recordIpsUsing()` | [What's Stored](security-log-and-emails.md#whats-stored) |
| Where emailed links start | `Keyring::linkRootUsing()` | [Emailed Links](security.md#emailed-links) |
| The models | `Keyring::useAuthenticatorModel()` and the other four | [The Keyring Facade](configuration.md#the-keyring-facade) |
| Which attributes are protected | `protected`, `Keyring::withoutProtection()` | [Protected Changes](protected-changes.md) |

Devices, email changes, and every sign-in method except the password are off until you turn them on. The [risk signals](risk.md) and [security notices](security-log-and-emails.md#security-emails) come from whatever your `KeyringServiceProvider` lists. The provider that `keyring:install` publishes starts with a set of each. An app without that provider has none.

## Replacing a Controller or Service

Keyring's controllers and services are resolved from the container. That means you can swap one out by binding your own class in the `register()` method of a service provider. Extend Keyring's class, and override whatever you need:

```php
use App\Http\Controllers\AuthenticatorController;
use Keyring\Http\Controllers\AuthenticatorController as KeyringAuthenticatorController;

$this->app->bind(KeyringAuthenticatorController::class, AuthenticatorController::class);
```

The services behind them work the same way. They include `Keyring\Login\SignIn`, `Keyring\Login\StepUp`, `Keyring\Changes\AuthenticatorChanges`, `EmailChanges` and `PasswordChanges`, `Keyring\Devices\DeviceManager`, `Keyring\Support\Throttle`, and `Keyring\WebAuthn\Ceremonies`. Their methods are public or protected, never private.

Think of this as a last resort. A class you've replaced stops receiving Keyring's fixes for whatever you override. So prefer an option or hook from the table above when one does the job. For everything else, call the parent class's method.

## Changing the Routes

To change the prefix or middleware, set `routes` to `false`, and call `Keyring::routes()` inside your own group. If you need to change a route itself, you may copy `vendor/keyring/keyring/routes/keyring.php` into your app, and load that copy instead. Keep the route names, though. Keyring's controllers, responses, and emailed links find routes by name. See [Routes](configuration.md#routes).

## What Stays Fixed

A few things have no switch. Turning them off would quietly remove a protection:

- Plain `EmailCode::class` is refused. `EmailCode::asExtraStep()` is the switch for it, and it says what you're accepting.
- A user can't remove their last way to sign in. Removing the last second factor also requires the password, typed again, and that password must be long enough to stand alone.
- An email change is confirmed from the new address and announced to the old one. The old address can undo it.
- Trusting a device takes a real second factor. A confirm page opened without a step-up behind it never accepts recovery codes.
- You can't drop the steps that check rate limits, the policy, and risk from the pipeline by accident. The `dangerouslyReplace()` method is there for when you mean it.
- Emailed links are never built from the request's `Host` header.

Keyring also needs Eloquent user models that use the `HasKeyring` trait, and a session guard. It doesn't sign users in with token guards.

The field names that forms post (`remember`, `trust`, `code`, `credential`, and `authenticator`), the route names, and the status slugs are fixed too. The [browser package](frontend.md) and your pages rely on them.
