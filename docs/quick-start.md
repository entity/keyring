# Quick Start

- [Installing](#installing)
- [Your Pages](#your-pages)
- [Testing](#testing)
- [Adding Features](#adding-features)
- [Adding Sign-In Methods](#adding-sign-in-methods)
- [What Keyring Does Without Being Asked](#what-keyring-does-without-being-asked)

Keyring starts as a small foundation: signing in with a password, signing out, and the challenge and confirm pages. Everything else is a feature or a sign-in method you add when your app needs it.

## Installing

```bash
composer require entity/keyring
php artisan keyring:install
php artisan migrate
```

> Keyring has no tagged release yet. Until it does, add the repository to your `composer.json` and require `entity/keyring:@dev`.

`keyring:install` asks which sign-in methods you want besides the password, which features to turn on, and whether to send the security emails NIST asks for. With `--no-interaction` you get the password, registration and password resets. You can add the rest later.

Add the trait to your user model, and keep Laravel's `hashed` cast on the password:

```php
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable
{
    use HasKeyring;
}
```

## Your Pages

Keyring is headless, like Fortify: it handles the requests, and you build the pages. With Inertia, it renders `auth/{page}` components. Without it, it renders Blade views named `auth.{page}`. A missing view throws an error that names the file to create and the data it receives.

To start, you need:

| Page | When |
|---|---|
| `login` | Always. |
| `challenge` | When you add a second sign-in method. It asks for the next factor. |
| `confirm` | When you use step-up. It's the challenge page for confirming. |
| `register` | With `Features::registration()`. |
| `forgot-password`, `reset-password` | With `Features::resetPasswords()`. |

A login page posts `email`, `password` and, optionally, `remember` to `/login`:

```blade
{{-- resources/views/auth/login.blade.php --}}
<form method="POST" action="{{ route('login.store') }}">
    @csrf
    <input name="email" type="email" value="{{ old('email') }}" autocomplete="username" required>
    <input name="password" type="password" autocomplete="current-password" required>
    @error('email') <p>{{ $message }}</p> @enderror
    <button>Sign in</button>
</form>
```

Users land on `home` from `config/keyring.php` once they're in, `/dashboard` unless you change it. Every page and its data is listed in [Pages](sign-in-flow.md#pages). The [example app](https://github.com/entity/keyring-example) has all of them in React.

## Testing

Use `InteractsWithKeyring` in your base test case. It adds `withAssurance()`, `freshAt()` and `sessionErrors()`, and skips the timing delay on failed checks:

```php
use Keyring\Testing\InteractsWithKeyring;

abstract class TestCase extends BaseTestCase
{
    use InteractsWithKeyring;
}
```

Add `KeyringConformance` to a test class to check that your setup keeps Keyring's guarantees. See [Testing](testing.md).

## Adding Features

Turn features on in `config/keyring.php`. Each one brings its routes, and anything else it needs, only once it's in the list:

```php
use Keyring\Features;

'features' => [
    Features::registration(),
    Features::resetPasswords(),
    Features::manageAuthenticators(),
],
```

| Feature | What it adds | Docs |
|---|---|---|
| `registration()` | `/register`, through your `CreateNewUser` action. | [Registration](sign-in-flow.md#registration) |
| `resetPasswords()` | Forgot and reset password, through your `ResetUserPassword` action. | [Resetting the Password](protected-changes.md#resetting-the-password) |
| `emailVerification()` | Laravel's email verification routes and the `verify-email` page. | [Email Verification](protected-changes.md#email-verification) |
| `updatePasswords()` | `PUT /user/password`. Changing the password elsewhere then throws. | [Changing the Password](protected-changes.md#changing-the-password) |
| `manageAuthenticators()` | Adding, renaming and removing sign-in methods. Needed for users to set any up. | [Managing Authenticators](authenticators.md) |
| `devices()` | A device cookie, "trust this device", a list of where users are signed in, and "this wasn't me" links. | [Devices & Sessions](devices-and-sessions.md) |
| `emailChanges()` | Email changes confirmed by the new address and undoable from the old one. Changing the email elsewhere then throws. | [Protected Changes](protected-changes.md#changing-the-email-address) |
| `securityLog()` | A log of sign ins, failures and changes, and "was this you?" alerts. | [Security Log & Emails](security-log-and-emails.md) |

Some things are set up in your `KeyringServiceProvider` instead, since they take code:

- [Risk signals](risk.md): `Keyring::risk([...])`.
- [Requiring a second factor](policies.md#requiring-a-second-factor): the `keyring.enrolled` middleware.
- Security emails: the `notifications` list in `config/keyring.php`. See [Security Emails](security-log-and-emails.md#security-emails).

## Adding Sign-In Methods

List them in `app/Providers/KeyringServiceProvider.php`, and turn on `Features::manageAuthenticators()` so users can set them up:

```php
Keyring::factors([
    Password::class,
    Totp::class,
    RecoveryCodes::class,
    WebAuthn::passkeys(),
]);

Keyring::require(Requirement::aal2()->ifEnrolled());
```

`Requirement::aal2()->ifEnrolled()` asks for a second factor once a user has set one up, as Fortify does. See [Factors](factors.md) and [Policies](policies.md).

## What Keyring Does Without Being Asked

These are part of the foundation. You don't need to set them up, but you can change them:

| What | Default | Change it with |
|---|---|---|
| Rate limits on signing in | 5 a minute per account, 20 per IP, and a factor refused after 100 failures in a row until a success or a password reset | `limits` in [Configuration](configuration.md#pending-logins-timebox-and-rate-limits) |
| Failed checks take the same time | 250ms | `timebox` |
| Password rules | 15 characters without a second factor, 8 with one. Common passwords and ones containing the user's or site's name are refused, and breached ones in production | [Password Rules](protected-changes.md#password-rules) |
| A record of each session, so Keyring can sign them out | Sessions end after 30 days, and "remember me" lasts no longer | `sessions` in [Configuration](configuration.md#sessions) |
| Assurance levels lapse, as NIST asks | AAL2 after an hour idle or 24 hours, AAL3 after 15 minutes or 12 hours | `sessions.levels` |
| Browsers are told to clear their cache and storage on sign out | On | A custom [`LogoutResponse`](sign-in-flow.md#responses) |
| Step-up middleware | `keyring:aal2` and `keyring.fresh:15m`, for your routes | [Step-Up](step-up.md) |
