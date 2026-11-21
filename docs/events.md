# Events

- [Introduction](#introduction)
- [Signing In and Confirming](#signing-in-and-confirming)
- [Sessions and Devices](#sessions-and-devices)
- [Authenticators](#authenticators)
- [Account Changes](#account-changes)
- [Risk](#risk)
- [Refusals](#refusals)
- [Laravel's Auth Events](#laravels-auth-events)

## Introduction

Every event lives in the `Keyring\Events` namespace, and its data is stored in public readonly properties. To listen for them, use the same approach you would for any Laravel event. For example, this listener saves the time of each sign in:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\Authenticated;

Event::listen(function (Authenticated $event) {
    $event->user->update(['last_signed_in_at' => now()]);
});
```

The `user` property is always an instance of your user model. Keyring fires events whether or not a feature that reacts to them is turned on. The [security log](security-log-and-emails.md) and the [security emails](security-log-and-emails.md#security-emails) are listeners for these same events, so your own listeners don't need either one.

No event has a password, code, or token among its properties, apart from the registry ID in the `session` of `SessionResumed` and `RememberMeReused`, which a listener in the request sees and a queued one doesn't (see below). `Attempting`, `FactorFailed`, and `Lockout` carry the request as it arrived, including whatever the user typed. Don't log or serialise that request in full, and don't queue a listener for those three events. Laravel's `Failed`, which Keyring dispatches with `FactorFailed`, carries your user model as it is, so don't queue a listener for it either.

Keyring's other events don't put a password hash, a secret, or a "remember me" value on your queue. A queued listener gets the `user` back from the database by its ID, as with any Laravel event that uses `SerializesModels`. An `attempt` is queued as its plain data and looks its user up again when you call `user()`. If the user has been deleted by then, `attempt->user()` and `attempt->keyring()` throw `AttemptExpired`. That happens in your listener, after the job has been restored, so `deleteWhenMissingModels` doesn't cover it: catch it, or let the job fail. `AuthenticatorRemoved` queues the deleted authenticator without its `secret`. `FactorChallenged` and `FactorVerified` queue their `authenticator` by its ID, so for a password, which has no stored authenticator, a queued listener can't get it back and the job fails.

`SessionResumed` and `RememberMeReused` carry a `RegisteredSession` whose `id` is the ["remember me" cookie](devices-and-sessions.md#remember-me)'s value. A listener in the request sees it, but a queued listener gets the record without any of its registry IDs: a blank `id`, and a null `replacedBy` and `origin`. Both events always carry the session's `handle` as well, worked out from the full record when the event is made. It's the same one the [sessions list](devices-and-sessions.md#listing-and-ending-sessions) shows, so use that to tell sessions apart. `Sessions::find($user, $event->handle)` turns it back into the session while it's still active. Don't call `Sessions::handle()` on the queued record: with its IDs gone it has no handle, and it throws a `LogicException`. Only serialising the event leaves the IDs out. Anything that reads the event's properties directly, such as Telescope's event watcher or a `dump()` or `json_encode()` of the event, still sees it.

## Signing In and Confirming

| Event | When | Properties |
|---|---|---|
| `Attempting` | A factor is about to be checked. | `request`, `factor` (its key), `purpose` |
| `FactorChallenged` | The challenge page showed a factor. | `attempt`, `authenticator` |
| `FactorVerified` | A factor's proof was right. | `attempt`, `authenticator`, `verification` |
| `FactorFailed` | A factor's proof was wrong, or the user wasn't found. | `attempt` (null when the user wasn't found), `authenticator` (nullable), `factor`, `request` |
| `Lockout` | A rate limit was hit. This includes an account's own limit refusing a sign in, which is answered like a wrong password. It's dispatched for every request the limit refuses. The [security log](security-log-and-emails.md#refusals-that-repeat) notes it once per lock. | `request`, `factor`, `retryAfter` (in seconds, or `null` when waiting won't help, meaning the factor stays refused until its failures in a row are cleared) |
| `AccountLocked` | Failed attempts have caused a factor that can start a sign in to be refused for the account until a password reset or `Keyring::unlock()`. This happens when the factor used up its failures in a row, or when `limits.lock_after` held it. Browsers the account has signed in from may still get in. | `user`, `factor` |
| `Authenticated` | A login completed, and the user was signed in. | `user`, `attempt`, `device` (null without `Features::devices()`) |
| `Confirmed` | A [step-up](step-up.md) completed. | `user`, `attempt` |
| `LoggedOut` | The user signed out. | `user` |

`purpose` is the `Keyring\Enums\Purpose` enum, either `Login` or `Confirm`. `FactorChallenged`, `FactorVerified`, and `FactorFailed` fire for both purposes, so check `$event->attempt?->purpose` when a listener should only react to sign ins. On `FactorFailed`, `attempt` is null when the user wasn't found. See [The Sign In Flow](sign-in-flow.md#events).

## Sessions and Devices

| Event | When | Properties |
|---|---|---|
| `NewDeviceSignedIn` | Someone signed in from a device the account hasn't used before. | `user`, `device`, and `revokeUrl($days = null)`. The link is valid for `devices.report_link_for` unless you pass a number of days. It's the ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link). |
| `DeviceRevoked` | A device was signed out. | `user`, `device`, `reported` (true when it came from the "this wasn't me" link) |
| `SessionsRevoked` | Sessions were signed out. This happens with "sign out everywhere else", when one session is ended from the sessions list, when an administrator runs `keyring:sign-out` for the user, or on the first request refused for an account [the application keeps out](sign-in-flow.md#who-may-sign-in). | `user`, `count` |
| `SessionEnded` | Keyring signed a session out on its own. | `user`, `reason`: `revoked`, `expired`, `idle`, `other_user`, `reused`, `risk`, or `not_allowed` |
| `SessionResumed` | ["Remember me"](devices-and-sessions.md#remember-me) signed a browser back in after its session had gone unused. Nothing was proved. | `user`, `session` (the `RegisteredSession` it carries on as), `handle` (the session's handle) |
| `RememberMeReused` | A ["remember me" cookie was used twice](devices-and-sessions.md#a-cookie-used-twice). This means two browsers held the same cookies, so the session was ended for both. | `user`, `session` (the `RegisteredSession` that was ended. Its device, IP address, and user agent belong to whoever used the cookie first.), `handle` (the session's handle) |

A user who signs out on purpose triggers `LoggedOut`, not `SessionEnded`. The request that brought a used cookie also gets a `SessionEnded` with `reused`. `RememberMeReused` fires once, and only when there was still a session to end. See [Devices & Sessions](devices-and-sessions.md#events).

## Authenticators

| Event | When | Properties |
|---|---|---|
| `AuthenticatorAdded` | The user added a sign-in method. | `user`, `authenticator` |
| `AuthenticatorRemoved` | The user removed one. | `user`, `authenticator` |
| `RecoveryCodesGenerated` | New recovery codes were made, and the old ones stopped working. | `user`, `authenticator` |
| `RecoveryCodeUsed` | A recovery code was used. | `authenticator`, `remaining` |
| `CloneSuspected` | A passkey or security key's counter went backwards, so the sign in was refused. | `authenticator` |

Confirming the `recovery` factor dispatches `RecoveryCodesGenerated` instead of `AuthenticatorAdded`. When an event has no `user` property, the owner is `$event->authenticator->user()`. See [Managing Authenticators](authenticators.md#events) and [Counters and Cloned Keys](passkeys.md#counters-and-cloned-keys).

## Account Changes

| Event | When | Properties |
|---|---|---|
| `EmailChangeRequested` | An email change was requested, and its links were sent. | `user`, `change` |
| `EmailChanged` | The email address changed. The old address can still revert the change for a while. | `user`, `change` |
| `EmailChangeReverted` | The old address undid a change. Every session was signed out. | `user`, `change` |
| `PasswordChanged` | The user changed their password. | `user` |
| `PasswordReset` | The password was reset from a reset link. Every session was signed out. | `user` |
| `PasswordChangeRequired` | A user was [held until they choose a new password](protected-changes.md#requiring-a-password-change). | `user`, `reason` (nullable) |
| `ProtectionBypassed` | Protected attributes were changed with [`Keyring::withoutProtection`](protected-changes.md#bypassing-protection). | `reason` (nullable) |

The `change` property is a `Keyring\Models\PendingChange`. Its tokens and addresses are hidden when it's serialised. See [Protected Changes](protected-changes.md#events).

## Risk

| Event | When | Properties |
|---|---|---|
| `RiskAssessed` | Keyring assessed the risk, and the action did something. | `user`, `risk`, `action`, `checkpoint` (`Checkpoint::Login` or `Checkpoint::Request`) |

An assessment that ends in `Action::allow` dispatches nothing. See [Risk](risk.md#events-and-logging).

## Refusals

| Event | When | Properties |
|---|---|---|
| `AccessRefused` | A signed-in user asked for an authenticator, device, or session that isn't theirs, or that doesn't exist. Both cases get the same 404, so the event doesn't tell them apart. The event also fires when someone opens an email verification link made for another account. | `user`, `resource` (`authenticator`, `device`, `session`, or `email_verification`), `id` (what was asked for, as it was sent. For a session, this is its handle.) |
| `RateLimited` | The form limiter refused a request to one of Keyring's routes, outside the sign-in limits. This covers registration, a reset, a change, an emailed link or the page it opens, and passkey options. | `user` (whoever is signed in, otherwise null), `limiter` (`keyring`, `keyring-pages`, or `keyring-login-options`), `route` (its name), `retryAfter` (in seconds) |
| `EnrollmentRefused` | A sign-in method wasn't added. | `user`, `factor`, `reason`: `invalid` (the factor turned the confirmation down, such as with a wrong code or a key it won't take) or `not_allowed` (the account may not add one yet) |
| `AuthenticatorRemovalRefused` | A sign-in method was kept, because removing it would have left the user unable to sign in the way their policy requires. | `user`, `authenticator` |
| `LinkRefused` | An emailed link was refused. This happens for a change that doesn't exist, a wrong or ended token, or a signature that didn't match or had expired. | `link`, `reason` (see [Refused Links](security-log-and-emails.md#refused-links)), `user` (whose email change it was, otherwise null) |
| `VerificationRefused` | A sign in or step-up met its requirement but was still refused, because a [mandatory step](sign-in-flow.md#mandatory-steps) hadn't run for the request. | `attempt`, `factor`, `skipped` (the steps' class names) |

None of these changes what the refused person sees. Each one fires every time, however often it's repeated. Only the [security log](security-log-and-emails.md#refusals-that-repeat) limits how many it writes down. A form that fails ordinary validation dispatches nothing.

That makes these events the right place to count from. Keyring keeps no metrics of its own, so if you watch for credential stuffing, you may feed your counters from a listener. To act on it at sign in instead, turn on the [`CredentialStuffing`](risk.md#built-in-signals) risk signal, which flags a sign in from an address where many other accounts have failed:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\FactorFailed;
use Keyring\Events\Lockout;
use Keyring\Events\RateLimited;

Event::listen(fn (FactorFailed $event) => Metrics::increment('auth.failed', ['factor' => $event->factor]));
Event::listen(fn (Lockout $event) => Metrics::increment('auth.locked_out', ['factor' => $event->factor]));
Event::listen(fn (RateLimited $event) => Metrics::increment('auth.rate_limited', ['route' => $event->route]));
```

`Metrics` stands for whatever your application reports to.

## Laravel's Auth Events

Keyring signs users in and out through the guard, so Laravel's `Login`, `Logout`, `Registered`, and `Verified` events fire as usual. `Registered` is dispatched once the response has been sent, unless [`registration.reveal_taken`](sign-in-flow.md#registration) is on. That way, the verification email it sends doesn't show up in how long a new address takes to get an answer. Keyring also dispatches these events alongside its own, so listeners and packages built for them keep working:

| Laravel Event | Dispatched With |
|---|---|
| `Illuminate\Auth\Events\Failed` | `FactorFailed`. Its credentials hold only the username field, never the password or code. |
| `Illuminate\Auth\Events\Lockout` | `Lockout`, so once for every refused request. |
| `Illuminate\Auth\Events\PasswordReset` | Keyring's `PasswordReset`. |
