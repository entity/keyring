# Managing Authenticators

- [Introduction](#introduction)
- [Routes](#routes)
- [Email Verification](#email-verification)
    - [Who May Enroll](#who-may-enroll)
- [Adding an Authenticator](#adding-an-authenticator)
    - [Beginning](#beginning)
    - [Confirming](#confirming)
- [Recovery Codes](#recovery-codes)
- [Renaming and Choosing the Default](#renaming-and-choosing-the-default)
- [Removing Authenticators](#removing-authenticators)
- [Signing Out Other Sessions](#signing-out-other-sessions)
- [Responses](#responses)
- [From JavaScript](#from-javascript)
- [From PHP](#from-php)
- [Events](#events)

## Introduction

One set of routes adds, renames and removes authenticators for every factor. There are no per-factor routes to register: when you add a factor, its enrollment works through the same endpoints. Turn them on with `Features::manageAuthenticators()`:

```php
'features' => [
    Features::manageAuthenticators(),
],
```

Without it, users can't set up any sign-in method besides the password themselves. `keyring:install` turns it on when you pick one.

## Routes

| Method | URI | Name | Does |
|---|---|---|---|
| `POST` | `/user/authenticators/{factor}` | `keyring.authenticators.store` | Begin: returns a QR code, WebAuthn options, recovery codes... |
| `POST` | `/user/authenticators/{factor}/confirm` | `keyring.authenticators.confirm` | Finish: prove it works. Uses the `keyring` rate limiter and the session lock. |
| `PATCH` | `/user/authenticators/{id}` | `keyring.authenticators.update` | Rename, or make it the default. |
| `DELETE` | `/user/authenticators/{id}` | `keyring.authenticators.destroy` | Remove it. Uses the `keyring` rate limiter, as it can check the password. |

These routes need `auth:{guard}`, plus the `changes_middleware` config option, `['keyring.fresh:15m']` by default. Users must have verified, in the last 15 minutes, as much as signing in would ask of them. See [Fresh Verification](step-up.md#fresh-verification).

`{factor}` must be a registered factor that implements `Enrollable`; otherwise the route returns a 404. Users can only see and change their own authenticators; anyone else's ID returns a 404.

## Email Verification

When your user model implements `MustVerifyEmail`, users must verify their email address before beginning or confirming an enrollment. Until then, both routes return a `403` with `keyring::keyring.verify_email_first`.

Until the address is verified, the account may belong to whoever typed that address first. Factors they added would survive the real owner's password reset.

So with `Features::registration()` on, where anyone can type any address, users must be able to verify theirs: your user model must implement `MustVerifyEmail`, with `Features::emailVerification()` on. Otherwise enrolling throws a `Keyring\Exceptions\EmailVerificationRequired` that says what to change. Without registration, accounts come from you (an admin, an import, an invitation), so this isn't required. `keyring:install` turns on email verification when you pick registration and a sign-in method.

### Who May Enroll

If your app proves addresses another way (a code at sign-up, single sign-on, an admin approving accounts), say who may add a sign-in method yourself. This replaces the rule above, including the exception:

```php
Keyring::allowEnrollmentWhen(fn (User $user) => $user->approved_at !== null);
```

A user it refuses gets the same `403`. Only return true once you know the account is its owner's: anything less brings back the takeover the rule is there to stop.

## Adding an Authenticator

Adding is always two steps. Nothing is saved until the second one succeeds.

### Beginning

`POST /user/authenticators/{factor}` starts an enrollment and keeps its secret state in the session for 15 minutes ([`enrollments.keep_for`](configuration.md#account-changes-and-enrollment)). Starting again replaces it. Starting one for a factor that sends a code counts toward the account's [three codes per 10 minutes](sign-in-flow.md#sending-codes). The response's `enrollment` holds what to show the user:

| Factor | Request fields | `enrollment` |
|---|---|---|
| `totp` | `name` (optional) | `secret`, `algorithm` (`SHA1` unless the factor is [set up with another](factors.md#authenticator-apps-totp)), `url` (`otpauth://`), `qr` (an SVG string) |
| `email-code` | `name` (optional) | `length`, `sent: true`. A code is sent to the current address. |
| `recovery` | none | `codes`: the new plain codes, shown once |
| `passkey`, `security-key` | none | `options`: WebAuthn creation options for the browser |

```json
{
  "status": "enrollment-started",
  "factor": "totp",
  "enrollment": {
    "secret": "JBSWY3DPEHPK3PXP...",
    "algorithm": "SHA1",
    "url": "otpauth://totp/Example:taylor%40example.com?secret=...",
    "qr": "<svg ...>...</svg>"
  }
}
```

Authenticator apps and email codes take an optional `name` when beginning or confirming (the one sent when confirming wins); passkeys and security keys take it when confirming. Names default to "Authenticator app", "Email", "Passkey" or "Security key", and are cut to 64 characters.

### Confirming

`POST /user/authenticators/{factor}/confirm` proves the enrollment works:

| Factor | Fields |
|---|---|
| `totp`, `email-code` | `code`, `name` (optional) |
| `recovery` | none: confirming means "I've saved these" |
| `passkey`, `security-key` | `credential` (the browser's response), `name` (optional) |

A wrong proof fails with `keyring::keyring.invalid`, and an expired or missing enrollment, or one that was already confirmed, with `keyring::keyring.enrollment_expired`, both on the factor's field (`code`, or `credential` for passkeys and security keys). Email enrollment codes keep their guess count between tries, like email codes at sign in.

On success, the response contains the new authenticator, presented the same way as on the challenge page:

```json
{
  "status": "authenticator-added",
  "authenticator": { "factor": "totp", "id": "01JC4...", "name": "Authenticator app" },
  "recoveryCodes": ["jbsw-y3dp-ehpk-3pxp-jbsw-y3dp-eh", "..."]
}
```

`recoveryCodes` is only there when Keyring generated recovery codes along with this authenticator (see below).

The user's first saved authenticator becomes their default (never recovery codes). A passkey or security key that's already registered, to anyone, can't be registered again. Confirming a factor that allows only one per user (`email-code`, `recovery`) replaces the one they had.

## Recovery Codes

The first time a user adds an extra factor and has no recovery codes, or has used them all, Keyring creates a set of eight and returns them as `recoveryCodes`. Show them once and ask the user to save them. This only happens when the `recovery` factor is registered.

To give the user a new set, enroll the `recovery` factor: begin returns the new `codes`, and confirming replaces the old set. A user only ever has one set. Recovery codes are a fallback, so confirming them without another second factor fails with `keyring::keyring.recovery_needs_second_factor` on `authenticator`, and no set is stored.

Each code works once. The challenge page shows how many are left (`remaining`), and `Keyring\Events\RecoveryCodeUsed` carries the count, so you can suggest new codes when they run low. Users with no codes left keep the (empty) set until they make a new one, add another factor (which replaces it with a new set) or it's removed along with their last factor. An empty set is never offered as a way in.

## Renaming and Choosing the Default

`PATCH /user/authenticators/{id}` accepts:

| Field | |
|---|---|
| `name` | Optional, up to 64 characters. |
| `default` | Optional boolean. `true` makes this the default and clears the flag on the user's others. Not allowed for recovery codes. |

The default authenticator is offered first when a second factor is needed. Recovery codes are a fallback, so they can't be made the default.

## Removing Authenticators

`DELETE /user/authenticators/{id}` removes an authenticator, unless what's left would leave the user unable to sign in, or unable to meet the policy (for policies without `ifEnrolled()`). That fails with `keyring::keyring.last_factor` on `authenticator`.

Recovery codes are only useful while there's a factor to recover, so when a user removes their last extra factor, their recovery codes go with it. The policy is checked against what will actually be left.

Removing an authenticator stops trusting all of the user's devices (see [Trusted Devices](devices-and-sessions.md#trusted-devices)).

The password can't be removed this way. It isn't stored in `keyring_authenticators`.

Removing the user's last second factor (the last one beyond recovery codes and email codes) also needs their current password in the request as `password`. Their password may have been as short as `min_with_mfa` while it had a second factor beside it, and on its own NIST SP 800-63B asks for `min_without_mfa`. Keyring only stores a hash, so it checks the length then: a missing or wrong password, or one that's too short, gets an error on `password` asking them to change it first.

## Signing Out Other Sessions

Someone else being signed in is often why a user adds or removes a sign-in method. Confirming an enrollment (new recovery codes included) and removing an authenticator both take an optional boolean, `sign_out_others`. When it's `true` and the change went through, Keyring signs the user out everywhere but here, as [`DELETE /user/sessions`](devices-and-sessions.md#listing-and-ending-sessions) does: every other session is revoked, the "remember me" token is changed, no other device stays trusted, a pending email change is cancelled, and this session carries on under a new ID.

```ts
await confirmEnrollment('totp', enrollment, { code, sign_out_others: true })
await removeAuthenticator(id, undefined, { signOutOthers: true })
```

It's off unless the request asks, so offer it as a checkbox next to the button. A password change is the other way round, [on unless told otherwise](protected-changes.md#changing-the-password), because everyone who was signed in knew the old password. A new passkey takes nothing away from a session that signed in without it, and an authenticator that's removed already stops counting in every session it was used in.

Anything but a boolean fails with an error on `sign_out_others` before the enrollment is spent, and a change that's refused ends no sessions.

## Responses

Every route answers with a [status response](sign-in-flow.md#status-responses). Requests that expect JSON (and aren't Inertia visits) get JSON with `status`, `message` and the extra data:

| Action | `status` | Also |
|---|---|---|
| Begin | `enrollment-started` | `factor`, `enrollment` |
| Confirm | `authenticator-added` | `authenticator`, `recoveryCodes` |
| Update | `authenticator-updated` | `authenticator` |
| Remove | `authenticator-removed` | |

Other requests are redirected back with the `status` flashed, and the extra data flashed under `keyring.result` (for example `session('keyring.result.enrollment')`). The [browser package](frontend.md#managing-authenticators) uses the JSON form.

## From JavaScript

```ts
import { beginEnrollment, confirmEnrollment, enroll, makeDefault, removeAuthenticator, renameAuthenticator } from '@entity/keyring'

// Passkeys, security keys and recovery codes need no input in between.
const { authenticator, recoveryCodes } = await enroll('passkey', { name: 'Laptop' })

// Authenticator apps: show the QR code, then ask for a code.
const { enrollment } = await beginEnrollment('totp')
// ...render enrollment.qr...
await confirmEnrollment('totp', enrollment, { code })

await renameAuthenticator(id, 'Work phone')
await makeDefault(id)
await removeAuthenticator(id)
```

`confirmEnrollment()` runs the browser's WebAuthn ceremony for `passkey` and `security-key`. These helpers throw a `KeyringRequestError` on failure, including the `423` from step-up. See [Frontend](frontend.md#managing-authenticators).

## From PHP

`$user->keyring` (or `Keyring::for($user)`) is a `Keyring\UserKeyring`:

```php
use Keyring\Enums\Category;

$user->keyring->all();                       // every confirmed authenticator, default first, then by priority
$user->keyring->default();                   // the default, or the first stored one
$user->keyring->of('security-key');          // one factor's authenticators
$user->keyring->find($id);
$user->keyring->has(Category::Possession);
$user->keyring->canMeet($requirement);
$user->keyring->canSignIn();                 // can anything start a login?
```

The result is cached on the model. Call `$user->keyring->refresh()` after changing authenticators in the same request.

`$user->authenticators()` is a normal Eloquent relationship if you need to query rows directly. Secrets, public keys and credential IDs are hidden when the model is serialised, and `secret` is encrypted at rest.

## Events

In `Keyring\Events`:

| Event | Properties |
|---|---|
| `AuthenticatorAdded` | `user`, `authenticator` |
| `AuthenticatorRemoved` | `user`, `authenticator` |
| `RecoveryCodesGenerated` | `user`, `authenticator` |
| `RecoveryCodeUsed` | `authenticator`, `remaining` |
| `EnrollmentRefused` | `user`, `factor`, `reason` (`invalid` or `not_allowed`) |
| `AuthenticatorRemovalRefused` | `user`, `authenticator` |
| `AccessRefused` | `user`, `resource`, `id` |

Confirming the `recovery` factor dispatches `RecoveryCodesGenerated` instead of `AuthenticatorAdded`.

The last three are what was turned away: a confirmation whose code or key was wrong (or an account that may not enroll yet), a removal that would have left the user unable to sign in, and a request for an authenticator that isn't the user's. Each is answered as before, a 422, 403 or 404, and written to the [security log](security-log-and-emails.md#entry-types).
