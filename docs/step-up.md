# Step-Up

- [Introduction](#introduction)
- [Raising Assurance](#raising-assurance)
- [Fresh Verification](#fresh-verification)
- [The Confirm Flow](#the-confirm-flow)
- [JSON Requests](#json-requests)
- [Laravel's Password Confirmation](#laravels-password-confirmation)
- [Events](#events)

## Introduction

Step-up asks a signed-in user to prove something again before continuing. Keyring has two middleware for it:

- `keyring:{level}` requires the session to have reached an [assurance level](policies.md#assurance-levels).
- `keyring.fresh:{window}` requires a verification within a time window.

Both work as route middleware or with Laravel's `#[Middleware]` attribute, which takes one middleware per attribute. Always put them after `auth`. They read the user from Keyring's guard (`Keyring::user()`), not the default one, and a request with no one signed in to that guard gets Laravel's usual `AuthenticationException`:

```php
use Illuminate\Routing\Attributes\Controllers\Middleware;

#[Middleware('auth')]
#[Middleware('keyring:aal2')]
class BillingController
{
    #[Middleware('keyring.fresh:15m')]
    public function destroy()
    {
        // ...
    }
}
```

```php
Route::delete('/account', [AccountController::class, 'destroy'])
    ->middleware(['auth', 'keyring.fresh:5m']);
```

## Raising Assurance

`keyring:aal2` lets the request through when the session has reached AAL2 or higher. `keyring:aal1` and `keyring:aal3` work the same way, and `keyring` on its own means `keyring:aal2`. An unknown level name throws an `InvalidArgumentException`.

It counts everything proved so far this session, so it only asks for what's missing. A user who signed in with a password is asked for a possession factor to reach AAL2; a user who signed in with a passkey is already at AAL2, and at AAL3 if the passkey stays on its device.

A level doesn't last the whole session. It lapses after its idle and overall limits (an hour without a request, or 24 hours, at AAL2 by default, as NIST SP 800-63B asks), and the next `keyring:aal2` route asks again. See [Timeouts](devices-and-sessions.md#timeouts). A [risk response](risk.md#checkpoints) can also clear it.

Users who don't have the authenticators to reach the level can't be helped by confirming. They're sent to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) with the `enroll-first` status, the same as the [`keyring.enrolled`](policies.md#requiring-a-second-factor) middleware does. JSON requests get a `403` with that status and the URL. Without an `enrollment_url`, they get a plain `403`.

To check the session's level in your own code, ask `Keyring\Sessions\SessionAssurance`:

```php
use Keyring\Enums\Assurance;
use Keyring\Sessions\SessionAssurance;

app(SessionAssurance::class)->level()->atLeast(Assurance::AAL2);
```

## Fresh Verification

`keyring.fresh:15m` lets the request through when the user verified, in the last 15 minutes, as much as signing in would ask of them. The window takes any [duration](configuration.md#durations) and defaults to `15m`.

- Users with only a password confirm with their password.
- Users with two factors prove both again, as NIST SP 800-63B asks before binding a new authenticator. A stolen session plus one phished factor can't add, remove or change anything.
- Users who have any possession factor (an authenticator app, a passkey, a security key, email or recovery codes) always use one.
- A policy the user can't fully meet yet (one that asks for a passkey they haven't added) counts as far as they can, so they can still add it.
- The window starts at the moment of verification and doesn't slide with activity. Using the app doesn't keep it fresh.
- Signing in counts as a verification, so a fresh login is fresh for step-up too.

Keyring uses `keyring.fresh:15m` on its own sensitive routes, through the `changes_middleware` config option (applied on top of `auth:{guard}`): managing authenticators and devices, changing the password, and starting an email change.

## The Confirm Flow

When a request needs step-up, Keyring starts a confirm attempt with the requirement and redirects to the confirm page. The flow is the same as the [login challenge](sign-in-flow.md#the-challenge-page), on its own routes:

| Method | URI | Name |
|---|---|---|
| `GET` | `/confirm/{factor?}` | `keyring.confirm.challenge` |
| `POST` | `/confirm/{factor}` | `keyring.confirm.verify` |
| `POST` | `/confirm/{factor}/send` | `keyring.confirm.send` |

These routes need a user signed in to Keyring's guard (`auth:{guard}`), and the verify and send routes take the session lock like the login challenge's. The page rendered is `confirm` (not `challenge`), with `purpose: "confirm"` and `canTrustDevice: false`. Visiting `/confirm` with no confirm attempt in progress, including after one times out, starts one that any one factor except a recovery code satisfies: it doesn't know what the user was doing, so a code spent there might not get them there. A user with nothing to confirm with (no password, and no other sign-in method) is sent to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) instead, or gets a `403` without one.

A page that asks again while a confirm attempt for the same requirement is in progress continues it, so what the user already proved isn't lost.

Recovery codes are only offered when using one could finish the confirm: what's left must not need another possession factor. A passkey-only user is asked for the passkey, not a code it couldn't finish without.

When the user has verified enough, Keyring:

1. regenerates the session ID, destroying the old one,
2. records the new verifications, which resets the [level's clocks](devices-and-sessions.md#timeouts), and raises the registered session's assurance,
3. sets Laravel's `auth.password_confirmed_at`,
4. dispatches `Keyring\Events\Confirmed`,
5. redirects to the intended URL, or `home`.

For a `GET` request, the intended URL is the page that needed step-up. For other methods, Laravel uses the previous URL instead, so the user comes back to the page with the form rather than to a URL they can't `GET`.

The confirm attempt expires after `pending_logins.keep_for`, like a login attempt. The user comes back to `/confirm` with `keyring::keyring.expired` on the field of the factor it asks for next.

## JSON Requests

Requests that expect JSON (and aren't Inertia visits) get a `423 Locked` response instead of a redirect:

```json
{
  "message": "Please confirm it's you to continue.",
  "redirect": "https://example.com/confirm"
}
```

Send the user to `redirect`, then let them try again. Keyring remembers the page that made the call (the `Referer`), so after confirming they come back to it. Protecting the page's own `GET` route with the same middleware also works, and asks up front when the page loads. See [Handling Step-Up in JavaScript](frontend.md#handling-step-up-in-javascript).

## Laravel's Password Confirmation

Confirming through Keyring also satisfies Laravel's `password.confirm` middleware, so routes that already use it keep working. The reverse isn't true: Laravel's own password confirmation doesn't count for Keyring's middleware.

## Events

`Keyring\Events\Confirmed` is dispatched with `user` and `attempt` when a confirmation completes. `FactorVerified`, `FactorFailed` and the other [verification events](sign-in-flow.md#events) fire as they do at login, with the `confirm` purpose.
