# Quick Start

- [Installing](#installing)
- [Your Pages](#your-pages)
- [Your Settings Page](#your-settings-page)
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

> Keyring has no tagged release yet. Until it does, install it from GitHub:
>
> ```bash
> composer config repositories.keyring vcs https://github.com/entity/keyring
> composer require entity/keyring:dev-main
> ```

`keyring:install` asks which sign-in methods you want besides the password, which features to turn on, and whether to email users when their password or sign-in methods change. Recovery codes come with any second sign-in method, so losing it isn't the end of an account. With `--no-interaction` you get the password, registration and password resets. You can add the rest later: every action is published, so a feature works as soon as it's in the list.

Add the trait to your user model, and keep Laravel's `hashed` cast on the password. If users register themselves and can add sign-in methods, they must verify their address first, so implement `MustVerifyEmail` too (the installer turns on email verification for you):

```php
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring;
}
```

Without the trait, signing in throws a `Keyring\Exceptions\MissingTrait` exception naming the model, rather than working without the protection it adds.

## Your Pages

Keyring is headless, like Fortify: it handles the requests, and you build the pages. With Inertia, it renders `auth/{page}` components. Without it, it renders Blade views named `auth.{page}`. A missing view throws an error that names the file to create and the data it receives. So does a missing Inertia component, when Inertia's `pages.ensure_pages_exist` option is on.

Keyring renders nine pages. You only need the ones for what you've turned on:

| Page | When |
|---|---|
| `login` | Always. |
| `challenge` | When you add a second sign-in method. It asks for the next factor. |
| `confirm` | When you use step-up, which the routes for adding sign-in methods do. It's the challenge page for confirming, and can render the same component. |
| `register` | With `Features::registration()`. It posts `name`, `email`, `password` and `password_confirmation` to `/register`. |
| `forgot-password`, `reset-password` | With `Features::resetPasswords()`. |
| `verify-email` | With `Features::emailVerification()`. It asks the user to click the link they were sent, with a button to send another. |
| `email-change` | With `Features::emailChanges()`. The emailed confirm and undo links land here, on a page with one button. |
| `device-report` | With `Features::devices()`. The "this wasn't me" link lands here, on a page with one button. |

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

Users land on `home` from `config/keyring.php` once they're in, `/dashboard` unless you change it. A new Laravel app has no `/dashboard` route, so add one or point `home` somewhere that exists. Every page and its data is listed in [Pages](sign-in-flow.md#pages). The [example app](https://github.com/entity/keyring-example) has all of them in React.

## Your Settings Page

The page where users manage their sign-in methods is yours too, at whatever URL you like. Keyring has no route that renders it. Your controller reads what to show, and the page calls Keyring's routes to change it:

```php
use Illuminate\Http\Request;
use Inertia\Inertia;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\Factor;
use Keyring\Devices\DeviceManager;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;

class SecurityController
{
    public function edit(Request $request, DeviceManager $devices)
    {
        $user = $request->user();

        return Inertia::render('settings/security', [
            'authenticators' => $user->keyring->all()
                ->reject(fn (Authenticator $authenticator) => $authenticator->isVirtual())
                ->map(fn (Authenticator $authenticator) => [
                    ...$authenticator->factor()->present($authenticator),
                    'isDefault' => $authenticator->is_default,
                    'lastUsedAt' => $authenticator->last_used_at?->toIso8601String(),
                ])
                ->values(),
            'enrollable' => Keyring::registered()
                ->filter(fn (Factor $factor) => $factor instanceof Enrollable)
                ->keys(),
            'devices' => $devices->list($request, $user),
            'activity' => Keyring::activity($user, 15)->map(fn ($event) => [
                'type' => $event->type,
                'factor' => $event->factor,
                'ip' => $event->ip,
                'at' => $event->created_at->toIso8601String(),
            ]),
        ]);
    }
}
```

| Prop | What it holds |
|---|---|
| `authenticators` | What the user has set up. `present()` gives each one's `factor`, `id` and `name`, plus `hint` (a masked address) for email codes and `remaining` for recovery codes. The password is a virtual authenticator with no row of its own, so it's left out. |
| `enrollable` | The keys of the factors a user can add, such as `totp` and `passkey`, for your "add" buttons. It includes `recovery`, which only works once the user has another second factor, so show it as "generate recovery codes" next to those rather than as a way to sign in. |
| `devices` | Where the user is signed in, with `Features::devices()`. The same list as [`GET /user/devices`](devices-and-sessions.md#listing-and-revoking-devices). |
| `activity` | Recent [security log](security-log-and-emails.md#showing-recent-activity) entries, with `Features::securityLog()`. |

From there the page uses Keyring's routes: [`/user/authenticators`](authenticators.md#routes) to add, rename and remove sign-in methods, [`/user/devices`](devices-and-sessions.md#routes) to sign devices out, [`PUT /user/password`](protected-changes.md#changing-the-password) and [`POST /user/email`](protected-changes.md#changing-the-email-address). The [browser package](frontend.md#managing-authenticators) wraps the authenticator routes, including the passkey ceremony.

Those routes need a [fresh verification](step-up.md#fresh-verification), 15 minutes by default. Put the same middleware on the page, after `auth`, so users confirm once when they open it rather than halfway through adding a passkey:

```php
Route::get('/settings/security', [SecurityController::class, 'edit'])
    ->middleware(['auth', 'verified', 'keyring.fresh:15m']);
```

Signing in or registering counts as a verification, so right after either the page opens without asking. A user who leaves the page open longer than that gets a `423` from the next JSON call, with a `redirect` to the confirm page:

1. Catch the `423` and send the browser to `redirect`.
2. The user confirms on your `confirm` page.
3. Keyring sends them back to the page they were on, and they try again.

[Handling Step-Up in JavaScript](frontend.md#handling-step-up-in-javascript) has the code for the first step.

## Testing

Use `InteractsWithKeyring` in your base test case. It adds `withAssurance()`, `verifiedWith()`, `freshAt()`, `totpCode()` and `sessionErrors()`, and skips the timing delay on failed checks:

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

A few more things are opt-in, but aren't in the features list:

- [Security emails](security-log-and-emails.md#security-emails): the `security_notices` list in `config/keyring.php`.
- [Risk signals](risk.md): `Keyring::risk()->signals([...])` in your `KeyringServiceProvider`.
- [Requiring a second factor](policies.md#requiring-a-second-factor): the `keyring.enrolled` middleware, with `enrollment_url` set to your page for adding one. Step-up sends users there too when they don't have what a route needs.

## Adding Sign-In Methods

List them in `app/Providers/KeyringServiceProvider.php`, and turn on `Features::manageAuthenticators()` so users can set them up:

```php
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;

Keyring::factors([
    Password::class,
    Totp::class,
    RecoveryCodes::class,
    WebAuthn::passkeys(),
]);

Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
```

`Requirement::aal2()->ifEnrolled()` asks for a second factor once a user has set one up, as Fortify does. `noDowngrade()` means a user with a passkey can't be talked into using something weaker. See [Factors](factors.md) and [Policies](policies.md).

## What Keyring Does Without Being Asked

These are part of the foundation. You don't need to set them up, but you can change them:

| What | Default | Change it with |
|---|---|---|
| Rate limits on signing in | 5 a minute per account, 20 per IP, and a factor refused after 100 failures in a row | `limits` in [Configuration](configuration.md#pending-logins-timebox-and-rate-limits) |
| Failed checks take the same time | 250ms | `timebox` |
| Password rules | 15 characters without a second factor, 8 with one. Common passwords and ones containing the user's or site's name are refused, and breached ones in production | [Password Rules](protected-changes.md#password-rules) |
| A record of each session, with its IP address and browser, so Keyring can sign it out | Sessions end after 30 days, and the "remember me" cookie lasts no longer | `sessions` in [Configuration](configuration.md#sessions) |
| Assurance levels lapse, as NIST asks | AAL2 after an hour idle or 24 hours, AAL3 after 15 minutes or 12 hours | `sessions.levels` |
| Browsers are told to clear their cache and storage on sign out | On | A custom [`LogoutResponse`](sign-in-flow.md#responses) |
| Step-up middleware | `keyring:aal2` and `keyring.fresh:15m`, for your routes | [Step-Up](step-up.md) |
