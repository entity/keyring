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

Every event Keyring dispatches is in the `Keyring\Events` namespace, and its data is in public readonly properties. Listen for them the way you would any Laravel event:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\Authenticated;

Event::listen(function (Authenticated $event) {
    $event->user->update(['last_signed_in_at' => now()]);
});
```

`user` is always your user model. Events fire whether or not a feature that reacts to them is on: the [security log](security-log-and-emails.md) and the [security emails](security-log-and-emails.md#security-emails) are listeners of these same events, so your own listeners don't need either.

No event has a password, code or token among its properties. `Attempting`, `FactorFailed` and `Lockout` do carry the request as it arrived, which includes what the user typed, so don't log or serialise it whole, and don't queue a listener for those three.

## Signing In and Confirming

| Event | When | Properties |
|---|---|---|
| `Attempting` | A factor is about to be checked. | `request`, `factor` (its key), `purpose` |
| `FactorChallenged` | The challenge page showed a factor. | `attempt`, `authenticator` |
| `FactorVerified` | A factor's proof was right. | `attempt`, `authenticator`, `verification` |
| `FactorFailed` | A factor's proof was wrong, or the user wasn't found. | `attempt` (null when the user wasn't found), `authenticator` (nullable), `factor`, `request` |
| `Lockout` | A rate limit was hit, including an account's own limit refusing a sign in that is answered like a wrong password. Dispatched for every request the limit refuses; the [security log](security-log-and-emails.md#refusals-that-repeat) notes it once per lock. | `request`, `factor`, `retryAfter` (seconds, or `null` when waiting won't help: the factor is refused until its failures in a row are cleared) |
| `AccountLocked` | Failed attempts got a factor that can start a sign in refused for the account until a password reset or `Keyring::unlock()`: it used up its failures in a row, or `limits.lock_after` held it. Browsers the account has signed in from may still get in. | `user`, `factor` |
| `Authenticated` | A login completed and the user was signed in. | `user`, `attempt`, `device` (null without `Features::devices()`) |
| `Confirmed` | A [step-up](step-up.md) completed. | `user`, `attempt` |
| `LoggedOut` | The user signed out. | `user` |

`purpose` is the `Keyring\Enums\Purpose` enum, `Login` or `Confirm`. The verification events fire for both, so check `$event->attempt->purpose` when a listener should only react to sign ins. See [The Sign In Flow](sign-in-flow.md#events).

## Sessions and Devices

| Event | When | Properties |
|---|---|---|
| `NewDeviceSignedIn` | Someone signed in from a device the account hasn't used before. | `user`, `device`, and `revokeUrl($days = null)` (valid for `devices.report_link_for` unless you pass days) for a ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link) |
| `DeviceRevoked` | A device was signed out. | `user`, `device`, `reported` (true when it came from the "this wasn't me" link) |
| `SessionsRevoked` | Sessions were signed out: "sign out everywhere else", one session ended from the sessions list, an administrator's `keyring:sign-out` for the user, or the first request refused for an account [the app keeps out](sign-in-flow.md#who-may-sign-in). | `user`, `count` |
| `SessionEnded` | Keyring signed a session out on its own. | `user`, `reason`: `revoked`, `expired`, `idle`, `other_user`, `reused`, `risk` or `not_allowed` |
| `RememberMeReused` | A ["remember me" cookie was used twice](devices-and-sessions.md#a-cookie-used-twice), so two browsers held the same ones, and the session was ended for both. | `user`, `session` (the `RegisteredSession` that was ended: its device, IP address and user agent are those of whoever used the cookie first) |

A user signing out on purpose is `LoggedOut`, not `SessionEnded`. The request that brought a used cookie also gets a `SessionEnded` with `reused`; `RememberMeReused` fires once, and only when there was still a session to end. See [Devices & Sessions](devices-and-sessions.md#events).

## Authenticators

| Event | When | Properties |
|---|---|---|
| `AuthenticatorAdded` | The user added a sign-in method. | `user`, `authenticator` |
| `AuthenticatorRemoved` | The user removed one. | `user`, `authenticator` |
| `RecoveryCodesGenerated` | New recovery codes were made, and the old ones stopped working. | `user`, `authenticator` |
| `RecoveryCodeUsed` | A recovery code was used. | `authenticator`, `remaining` |
| `CloneSuspected` | A passkey or security key's counter went backwards, and the sign in was refused. | `authenticator` |

Confirming the `recovery` factor dispatches `RecoveryCodesGenerated` instead of `AuthenticatorAdded`. Where an event has no `user`, the owner is `$event->authenticator->user()`. See [Managing Authenticators](authenticators.md#events) and [Counters and Cloned Keys](passkeys.md#counters-and-cloned-keys).

## Account Changes

| Event | When | Properties |
|---|---|---|
| `EmailChangeRequested` | An email change was requested and its links were sent. | `user`, `change` |
| `EmailChanged` | The email address changed. The old address can still revert it for a while. | `user`, `change` |
| `EmailChangeReverted` | The old address undid a change. Every session was signed out. | `user`, `change` |
| `PasswordChanged` | The user changed their password. | `user` |
| `PasswordReset` | The password was reset from a reset link. Every session was signed out. | `user` |
| `PasswordChangeRequired` | A user was [held until they choose a new password](protected-changes.md#requiring-a-password-change). | `user`, `reason` (nullable) |
| `ProtectionBypassed` | Protected attributes were changed with [`Keyring::withoutProtection()`](protected-changes.md#bypassing-protection). | `reason` (nullable) |

`change` is a `Keyring\Models\PendingChange`. Its tokens and addresses are hidden when it's serialised. See [Protected Changes](protected-changes.md#events).

## Risk

| Event | When | Properties |
|---|---|---|
| `RiskAssessed` | Risk was assessed and the action did something. | `user`, `risk`, `action`, `checkpoint` (`Checkpoint::Login` or `Checkpoint::Request`) |

An assessment that ends in `Action::allow()` dispatches nothing. See [Risk](risk.md#events-and-logging).

## Refusals

| Event | When | Properties |
|---|---|---|
| `AccessRefused` | A signed-in user asked for an authenticator, device or session that isn't theirs, or that doesn't exist (both get the same 404, so the event doesn't tell them apart), or opened an email verification link made for another account. | `user`, `resource` (`authenticator`, `device`, `session` or `email_verification`), `id` (what was asked for, as it was sent; for a session, its handle) |
| `EnrollmentRefused` | A sign-in method wasn't added. | `user`, `factor`, `reason`: `invalid` (the factor turned the confirmation down: a wrong code, a key it won't take) or `not_allowed` (the account may not add one yet) |
| `AuthenticatorRemovalRefused` | A sign-in method was kept, because removing it would have left the user unable to sign in the way their policy requires. | `user`, `authenticator` |
| `LinkRefused` | An emailed link was refused: a change that doesn't exist, a wrong or ended token, or a signature that didn't match or had expired. | `link`, `reason` (see [Refused Links](security-log-and-emails.md#refused-links)), `user` (whose email change it was, otherwise null) |
| `VerificationRefused` | A sign in or step-up met its requirement and was still refused, because a [mandatory step](sign-in-flow.md#mandatory-steps) hadn't run for the request. | `attempt`, `factor`, `skipped` (the steps' class names) |

None of these changes what the person who was refused sees. Each fires every time, however often it's repeated: only the [security log](security-log-and-emails.md#refusals-that-repeat) limits how many it writes down. A form that fails ordinary validation dispatches nothing.

## Laravel's Auth Events

Keyring signs users in and out through the guard, so Laravel's `Login`, `Logout`, `Registered` and `Verified` events fire as usual. `Registered` is dispatched once the response has been sent, unless [`registration.reveal_taken`](sign-in-flow.md#registration) is on, so the verification email it sends doesn't show in how long a new address takes to answer. Like Fortify, it also dispatches these next to its own, so listeners and packages built for them keep working:

| Laravel event | Dispatched with |
|---|---|
| `Illuminate\Auth\Events\Failed` | `FactorFailed`. Its credentials hold only the username field, never the password or code. |
| `Illuminate\Auth\Events\Lockout` | `Lockout`, so once for every refused request. |
| `Illuminate\Auth\Events\PasswordReset` | Keyring's `PasswordReset`. |
