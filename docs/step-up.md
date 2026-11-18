# Step-Up

- [Introduction](#introduction)
- [Raising Assurance](#raising-assurance)
- [Fresh Verification](#fresh-verification)
- [The Confirm Flow](#the-confirm-flow)
- [JSON Requests](#json-requests)
- [Laravel's Password Confirmation](#laravels-password-confirmation)
- [Events](#events)

## Introduction

Step-up asks a signed-in user to prove something again before they continue. Keyring provides two middleware for this:

- `keyring:{level}` requires the session to have reached an [assurance level](policies.md#assurance-levels).
- `keyring.fresh:{window}` requires a verification within a time window.

You may use either one as route middleware, or with Laravel's `#[Middleware]` attribute, which takes one middleware per attribute. Always place them after `auth`. They read the user from Keyring's guard (`Keyring::user()`), not the default guard. A request with nobody signed in to that guard gets Laravel's usual `AuthenticationException`. For example:

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

Or, if you prefer to attach it to a route definition:

```php
Route::delete('/account', [AccountController::class, 'destroy'])
    ->middleware(['auth', 'keyring.fresh:5m']);
```

## Raising Assurance

`keyring:aal2` lets the request through when the session has reached AAL2 or higher. `keyring:aal1` and `keyring:aal3` work the same way. On its own, `keyring` means `keyring:aal2`. An unknown level name throws an `InvalidArgumentException`.

`keyring:aal3` needs a key that was added with a [verified attestation](passkeys.md#attestation-and-aal3). An app that doesn't check attestation can ask for more of AAL2 by name instead. `keyring:aal2,device-bound` requires a phishing-resistant key that stays on its device, among what the session proved. `keyring:aal2,phishing-resistant` requires any passkey or security key. [`keyring.enrolled`](policies.md#requiring-a-second-factor) takes the same names.

It counts everything proved so far this session, so it only asks for what's missing. An emailed code isn't a factor, so it counts for nothing here. A user who signed in with a password is asked for a possession factor to reach AAL2. A user who signed in with a passkey is already at AAL2. That user is at AAL3 too, if the passkey stays on its device and was added with a verified attestation.

A level doesn't last for the whole session. It lapses after its idle and overall limits. By default, at AAL2, those are an hour without a request or 24 hours, as NIST SP 800-63B-4 asks. After that, the next `keyring:aal2` route asks again. See [Timeouts](devices-and-sessions.md#timeouts). To end the session at that point instead, see [Ending a Session With Its Level](devices-and-sessions.md#ending-a-session-with-its-level). The idle limit is tracked by the [session middleware](devices-and-sessions.md#the-session-registry), which Keyring adds to the `web` group. Routes outside that group, such as Sanctum's `api` group, need `keyring.session` too. A [risk response](risk.md#checkpoints) can also clear a level. An authenticator that's removed stops counting in every session it was used in.

Users who don't have the authenticators to reach a level can't get there by confirming. Instead, they're sent to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) with the `enroll-first` status, the same as the [`keyring.enrolled`](policies.md#requiring-a-second-factor) middleware does. JSON requests get a `403` with that status and the URL. Without an `enrollment_url`, they get a plain `403`.

To check the session's level in your own code, ask `Keyring\Sessions\SessionAssurance`:

```php
use Keyring\Enums\Assurance;
use Keyring\Sessions\SessionAssurance;

app(SessionAssurance::class)->level()->atLeast(Assurance::AAL2);
```

## Fresh Verification

`keyring.fresh:15m` lets the request through when the user verified, in the last 15 minutes, the strongest combination their account can give, and at least as much as signing in would ask of them. The window takes any [duration](configuration.md#durations), and it defaults to `15m`.

NIST SP 800-63B-4 (Sec. 4.1.2.1) binds a new authenticator at the highest level the account can authenticate at, or at the level the new one will be used at if that's lower. Keyring always asks for the highest level, so what's asked here follows the account, not the sign-in policy:

- Users with only a password confirm with their password, so an account can always add its first sign-in method.
- Users with two factors prove both again, even where the policy would sign them in with one. A stolen session plus one phished factor can't add, remove, or change anything.
- Users with a key that can't leave its device use that key, with its own user verification or their password alongside it. A password and an authenticator app's code isn't enough for them, whatever the policy says. This applies to an attested key, which could reach AAL3, and to a key that nothing vouches for.
- A recovery code stands in for a lost key, along with the password, as it does at sign in. A policy that takes no codes there (`noDowngrade(except: [])`, or an explicit `phishingResistant()`) takes none here either. A code is never the whole of a confirmation. A user whose only other sign-in method is a set of recovery codes confirms with the password, and isn't offered the codes.
- Users who have any possession factor (an authenticator app, a passkey, or a security key) always use one. An [email code](factors.md#email-codes) isn't a possession factor, so it can't stand in. A user whose only other sign-in method is an emailed code proves the password and that code. That's what lets them add a real second factor.
- A policy the user can't fully meet yet, such as one that asks for a passkey they haven't added, counts as far as they can go, so they can still add it.
- A policy that asks for more than that is honoured. A [policy closure](policies.md#deciding-per-user-and-attempt) is asked about the browser the request comes from, and about an attempt nothing is known of, and the stricter answer stands. A policy that asks more of a new device is honored, and a trusted device gets no discount. Risk isn't assessed again, so a policy that reads `$attempt->risk` is asked with none.
- The window starts at the moment of verification, and it doesn't slide with activity. Using the app doesn't keep it fresh.
- Signing in counts as a verification, so a fresh login is also fresh for step-up. So does [adding a sign-in method](authenticators.md#confirming), for the method that was added.

Keyring uses `keyring.fresh:15m` on its own sensitive routes. It applies this through the `changes_middleware` config option, on top of `auth:{guard}`. Those routes cover managing authenticators and devices, changing the password, and starting an email change.

## The Confirm Flow

When a request needs step-up, Keyring starts a confirm attempt with the requirement, and redirects to the confirm page. The flow is the same as the [login challenge](sign-in-flow.md#the-challenge-page), but it uses its own routes:

| Method | URI | Name |
|---|---|---|
| `GET` | `/confirm/{factor?}` | `keyring.confirm.challenge` |
| `POST` | `/confirm/{factor}` | `keyring.confirm.verify` |
| `POST` | `/confirm/{factor}/send` | `keyring.confirm.send` |

These routes need a user signed in to Keyring's guard (`auth:{guard}`). The page, and its verify and send routes, take the session lock, as the login challenge does. The page rendered is `confirm` (not `challenge`), with `purpose: "confirm"` and `canTrustDevice: false`. Visiting `/confirm` with no confirm attempt in progress, including after one times out, starts one. Any single factor except a recovery code satisfies that attempt. Keyring doesn't know what the user was doing, so a code spent there might not get them there. A user with nothing to confirm with (no password, and no other sign-in method) is sent to your [`enrollment_url`](configuration.md#account-changes-and-enrollment) instead. Without one, they get a `403`.

If a page asks again while a confirm attempt for the same requirement is in progress, it continues that attempt. That way, what the user already proved isn't lost.

Recovery codes are only offered when using one could finish the confirm. In other words, what's left must not need another possession factor. A passkey-only user is asked for the passkey, not a code that would leave the confirm unfinished.

Once the user has verified enough, Keyring does the following:

1. regenerates the session ID, which destroys the old one,
2. records the new verifications, which resets the [level's clocks](devices-and-sessions.md#timeouts), and raises the registered session's assurance,
3. sets Laravel's `auth.password_confirmed_at`,
4. dispatches `Keyring\Events\Confirmed`,
5. redirects to the intended URL, or `home`.

For a `GET` request, the intended URL is the page that needed step-up. For other methods, Laravel uses the previous URL instead. That way, the user returns to the page with the form, rather than to a URL they can't `GET`.

The confirm attempt expires after `pending_logins.keep_for`, in the same way as a login attempt. When it expires, the user returns to `/confirm`, and `keyring::keyring.expired` appears on the field of the factor it asks for next.

## JSON Requests

Requests that expect JSON (and aren't Inertia visits) get a `423 Locked` response instead of a redirect:

```json
{
  "message": "Please confirm it's you to continue.",
  "redirect": "https://example.com/confirm"
}
```

Send the user to `redirect`, and then let them try again. Keyring remembers the page that made the call (the `Referer`), so after confirming, the user comes back to it. You may also protect the page's own `GET` route with the same middleware. That works too, and it asks up front when the page loads. See [Handling Step-Up in JavaScript](frontend.md#handling-step-up-in-javascript).

## Laravel's Password Confirmation

Confirming through Keyring also satisfies Laravel's `password.confirm` middleware, so routes that already use it keep working. The reverse isn't true. Laravel's own password confirmation doesn't count for Keyring's middleware.

## Events

Keyring dispatches `Keyring\Events\Confirmed` with `user` and `attempt` when a confirmation completes. The `FactorVerified` and `FactorFailed` events, along with the other [verification events](sign-in-flow.md#events), fire as they do at login, with the `confirm` purpose.
