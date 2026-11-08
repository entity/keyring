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

Both work as route middleware or with Laravel's `#[Middleware]` attribute, which takes one middleware per attribute. Always put them after `auth`:

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

`keyring:aal2` lets the request through when the session has reached AAL2 or higher. `keyring:aal1` and `keyring:aal3` work the same way, and `keyring` on its own means `keyring:aal2`.

It counts everything proved so far this session, so it only asks for what's missing. A user who signed in with a password is asked for a possession factor to reach AAL2; a user who signed in with a passkey is already at AAL3 and goes straight through.

The level stays reached for the rest of the session, unless a [risk response](risk.md#checkpoints) clears it.

Users who don't have the authenticators to reach the level can't get through. The confirm page shows `keyring::keyring.unavailable` and offers a plain confirmation instead, which doesn't raise their level, so they're asked again. Send these users to set up a factor first, for example by checking `$request->user()->keyring->canMeet(Requirement::aal2())` before linking to the route.

## Fresh Verification

`keyring.fresh:15m` lets the request through when the user verified a factor in the last 15 minutes. The window takes any [duration](configuration.md#durations) and defaults to `15m`.

- Users with only a password confirm with their password.
- Users who have any possession factor (an authenticator app, a passkey, a security key, email or recovery codes) must use one. A stolen session plus a phished password can't be used to add or remove factors.
- The window starts at the moment of verification and doesn't slide with activity. Using the app doesn't keep it fresh.
- Signing in counts as a verification, so a fresh login is fresh for step-up too.

Keyring uses `keyring.fresh:15m` on its own sensitive routes, through the `manage_middleware` config option: managing authenticators and devices, changing the password, and starting an email change.

## The Confirm Flow

When a request needs step-up, Keyring starts a confirm attempt with the requirement and redirects to the confirm page. The flow is the same as the [login challenge](sign-in-flow.md#the-challenge-page), on its own routes:

| Method | URI | Name |
|---|---|---|
| `GET` | `/confirm/{factor?}` | `keyring.confirm.challenge` |
| `POST` | `/confirm/{factor}` | `keyring.confirm.verify` |
| `POST` | `/confirm/{factor}/send` | `keyring.confirm.send` |

These routes need a signed-in user. The page rendered is `confirm` (not `challenge`), with `purpose: "confirm"` and `canTrustDevice: false`. Visiting `/confirm` with no confirm attempt in progress starts one that any one factor satisfies.

When the user has verified enough, Keyring:

1. regenerates the session ID,
2. records the new verifications, and raises the registered session's assurance (which can shorten its [absolute timeout](devices-and-sessions.md#timeouts)),
3. sets Laravel's `auth.password_confirmed_at`,
4. dispatches `Keyring\Events\Confirmed`,
5. redirects to the intended URL, or `home`.

For a `GET` request, the intended URL is the page that needed step-up. For other methods, Laravel uses the previous URL instead, so the user comes back to the page with the form rather than to a URL they can't `GET`.

The confirm attempt expires after `pending_login_ttl` seconds like a login attempt.

## JSON Requests

Requests that expect JSON (and aren't Inertia visits) get a `423 Locked` response instead of a redirect:

```json
{
  "message": "Please confirm it's you to continue.",
  "redirect": "https://example.com/confirm"
}
```

Send the user to `redirect`, then let them try again. In this case Keyring doesn't remember where the user came from, so after confirming they land on the intended URL from earlier in the session, or `home`. If you want users to come back to a settings page, protect that page's `GET` route with the same middleware, so step-up happens when the page loads. See [Handling Step-Up in JavaScript](frontend.md#handling-step-up-in-javascript).

## Laravel's Password Confirmation

Confirming through Keyring also satisfies Laravel's `password.confirm` middleware, so routes that already use it keep working. The reverse isn't true: Laravel's own password confirmation doesn't count for Keyring's middleware.

## Events

`Keyring\Events\Confirmed` is dispatched with `user` and `attempt` when a confirmation completes. `FactorVerified`, `FactorFailed` and the other [verification events](sign-in-flow.md#events) fire as they do at login, with the `confirm` purpose.
