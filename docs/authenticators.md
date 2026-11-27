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
- [Frozen Sign-In Methods](#frozen-sign-in-methods)
    - [Established Authenticators](#established-authenticators)
    - [Getting Past the Freeze](#getting-past-the-freeze)
- [Signing Out Other Sessions](#signing-out-other-sessions)
- [Responses](#responses)
- [From JavaScript](#from-javascript)
- [From PHP](#from-php)
- [Events](#events)

## Introduction

A [factor](factors.md) is a kind of sign-in method, such as an authenticator app or a passkey. An authenticator is one that a user has set up. A single set of routes adds, renames, and removes authenticators for every factor. You don't need to register any per-factor routes. When you add a factor, its enrollment works through the same endpoints. To turn these routes on, enable the `Features::manageAuthenticators()` feature:

```php
'features' => [
    Features::manageAuthenticators(),
],
```

Without this feature, users have no way to set up a sign-in method besides the password for themselves. The `keyring:install` command turns it on when you choose a sign-in method.

## Routes

| Method | URI | Name | Does |
|---|---|---|---|
| `POST` | `/user/authenticators/{factor}` | `keyring.authenticators.store` | Begins an enrollment: returns a QR code, WebAuthn options, recovery codes, and so on. Uses the session lock. |
| `POST` | `/user/authenticators/{factor}/confirm` | `keyring.authenticators.confirm` | Finishes it by proving the new authenticator works. Uses the `keyring` rate limiter and the session lock. |
| `PATCH` | `/user/authenticators/{authenticator}` | `keyring.authenticators.update` | Renames the authenticator, or makes it the default. |
| `DELETE` | `/user/authenticators/{authenticator}` | `keyring.authenticators.destroy` | Removes the authenticator. Uses the `keyring` rate limiter, because it may check the password. |

These routes require `auth:{guard}` middleware, along with the middleware set in the `changes_middleware` configuration option. By default, that is `['keyring.fresh:15m']`. Users must have verified, within the last 15 minutes, the strongest combination their account can offer. For example, someone with a key that can't leave its device uses that key before adding another, and someone with only a password uses the password. See [Fresh Verification](step-up.md#fresh-verification).

The `{factor}` segment must be a registered factor that implements `Enrollable`. If it isn't, the route returns a 404. The check for whether the user may enroll comes first, so an unverified user gets the `403` even for a key that isn't registered. Users can only see and change their own authenticators, and requesting anyone else's ID also returns a 404.

## Email Verification

When your user model implements `MustVerifyEmail`, users must verify their email address before they begin or confirm an enrollment. Until they do, both routes return a `403` response with `keyring::keyring.verify_email_first`.

Until an address is verified, the account may belong to whoever typed that address first. Any factors they added would survive the real owner's password reset.

For that reason, when `Features::registration()` is on, anyone can type any address, so users must be able to verify theirs. Your user model must implement `MustVerifyEmail`, and `Features::emailVerification()` must be on. Otherwise, enrolling throws a `Keyring\Exceptions\EmailVerificationRequired` exception that explains what to change.

Without registration, accounts come from you, through an admin, an import, or an invitation, so verification isn't required.

> [!NOTE]
> The `keyring:install` command turns on email verification whenever you choose registration. Registration [needs it by default](sign-in-flow.md#without-revealing-who-has-an-account) for its own reasons: there, nobody is signed in at all until their address is verified.

### Who May Enroll

If your application proves addresses another way, such as with a code at sign-up, single sign-on, or an admin approving accounts, you may decide who can add a sign-in method yourself. Your callback takes the place of the whole rule above. Keyring no longer checks for a verified address, and it no longer throws `EmailVerificationRequired`:

```php
Keyring::allowEnrollmentWhen(fn (User $user) => $user->approved_at !== null);
```

A user this check refuses gets the same `403`. Only return `true` once you know the account belongs to its owner. Anything less brings back the takeover that the rule is there to stop.

## Adding an Authenticator

Adding an authenticator always takes two steps. Nothing is saved until the second one succeeds.

### Beginning

`POST /user/authenticators/{factor}` starts an enrollment. It keeps the enrollment's secret state in the session for 15 minutes ([`enrollments.keep_for`](configuration.md#account-changes-and-enrollment)). Starting again replaces the previous enrollment. If the factor sends a code, starting it counts toward the account's [three codes per 10 minutes](sign-in-flow.md#sending-codes). The `enrollment` in the response holds what you should show the user:

| Factor | Request Fields | `enrollment` |
|---|---|---|
| `totp` | `name` (optional) | `secret`, `algorithm` (`SHA1` unless the factor is [set up with another](factors.md#authenticator-apps-totp)), `url` (`otpauth://`), `qr` (an SVG string) |
| `email-code` | `name` (optional) | `length`, and `sent: true`. A code is sent to the current address. |
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

Authenticator apps and email codes accept an optional `name` when beginning or confirming. If you send one in both places, the name sent when confirming wins. Passkeys and security keys accept a `name` when confirming. If no name is sent, it defaults to "Authenticator app", "Email", "Passkey", or "Security key", depending on the factor. A name given when beginning is cut to 64 characters. When confirming, a name over 64 characters is refused with a `422` on `name`, which is what passkeys and security keys get, since they only take one then. A name that isn't valid UTF-8, or that holds a NUL character, is refused with an error on `name`.

### Confirming

`POST /user/authenticators/{factor}/confirm` proves that the enrollment works:

| Factor | Fields |
|---|---|
| `totp`, `email-code` | `code`, `name` (optional) |
| `recovery` | none: confirming means "I've saved these" |
| `passkey`, `security-key` | `credential` (the browser's response), `name` (optional) |

A wrong proof fails with `keyring::keyring.invalid`. An expired or missing enrollment, or one that has already been confirmed, fails with `keyring::keyring.enrollment_expired`. Both errors appear on the factor's field: `code`, or `credential` for passkeys and security keys. Email enrollment codes keep their guess count between tries, as email codes at sign in do.

On success, the response contains the new authenticator, as its factor's `present` method gives it:

```json
{
  "status": "authenticator-added",
  "authenticator": { "factor": "totp", "id": "01JC4...", "name": "Authenticator app", "createdAt": "2026-11-08T14:05:00+00:00", "lastUsedAt": null },
  "recoveryCodes": ["jbsw-y3dp-ehpk-3pxp-jbsw-y3dp-eh", "..."]
}
```

`createdAt` and `lastUsedAt` record when the authenticator was added and last used to sign in or confirm. They're ISO 8601 dates, and they're meant for the list on your settings page. OWASP's Passkey Security Cheat Sheet suggests that a page managing credentials shows both. The [challenge page](sign-in-flow.md#page-props) gets the same shape, without them.

The `recoveryCodes` key only appears when Keyring generated recovery codes along with this authenticator (see below).

The first authenticator a user saves becomes their default, though recovery codes never do. A passkey or security key that's already registered, to anyone, can't be registered again. Confirming a factor that allows only one per user (`email-code` or `recovery`) replaces the one they already have.

Confirming an authenticator also proves it, so the session counts it as verified, in the same way as a sign in. For example, a user who signed in with a password and then adds an authenticator app reaches [AAL2](policies.md#assurance-levels) with that response. The session ID changes, as it does after any proof. This is also why the first recovery codes can be shown at that point. NIST SP 800-63B-4 (Sec. 3.1.2.1) expects codes delivered online to go to a session that has proved two factors. New recovery codes prove nothing and count for nothing, and nothing proved earlier becomes any fresher.

## Recovery Codes

The first time a user adds an extra factor while they have no recovery codes, or have used them all, Keyring creates a set of eight and returns them as `recoveryCodes`. Show them once, and ask the user to save them. This only happens when the `recovery` factor is registered. An [email code](factors.md#email-codes) doesn't count as a second factor, so adding one comes with no codes.

To give the user a new set, enroll the `recovery` factor. Beginning returns the new `codes`, and confirming replaces the old set. A user only ever has one set. Replacing a set that has codes left is refused while the account's sign-in methods are [frozen](#frozen-sign-in-methods), both when beginning and when confirming. Making the first set, or replacing one with no codes left, never is. Recovery codes are a fallback, so confirming them without another second factor fails with `keyring::keyring.recovery_needs_second_factor` on `authenticator`, and no set is stored. An email code doesn't count as that second factor.

Each code works only once. The challenge page shows how many are left as `remaining`, and the `Keyring\Events\RecoveryCodeUsed` event carries the same count.

NIST SP 800-63B-4 (Sec. 4.2.1.1) says a new code should be issued once one is used. A new code is only worth something once the user has seen and saved it, so Keyring doesn't generate one behind the user's back. Instead, it marks the set and tells your application, which then sends the user to make a new set:

- `$user->keyring->shouldReplaceRecoveryCodes()` is true from the moment a code is used until the set is replaced, however many times the user signs in meanwhile.
- The set's [presentation](sign-in-flow.md#page-props) includes the same answer as `replace`, next to `remaining`, wherever you list authenticators.

To share this with your pages, add it to the props your `HandleInertiaRequests` middleware shares. Then show a banner that links to where users generate codes, or redirect them there after a sign in:

```php
// app/Http/Middleware/HandleInertiaRequests.php
'replaceRecoveryCodes' => fn () => (bool) $request->user()?->keyring->shouldReplaceRecoveryCodes(),
```

This loads the user's authenticators, so keep it lazy, as shown above. A session that signed in a moment ago with a recovery code and its password is fresh. It can generate the new set straight away without confirming again. Until your application does this, a used code is spent and nothing takes its place. NIST's rule is only met once the user has their new set.

Users with no codes left keep the empty set until they make a new one, add another factor (which replaces it with a new set), or remove it along with their last factor. An empty set is never offered as a way in.

## Renaming and Choosing the Default

`PATCH /user/authenticators/{authenticator}` accepts these fields:

| Field | Description |
|---|---|
| `name` | Optional, up to 64 characters of valid UTF-8. |
| `default` | An optional boolean. Passing `true` makes this authenticator the default, and clears the flag on the user's others. This isn't allowed for recovery codes. |

The default authenticator is offered first when a second factor is needed. Recovery codes are only a fallback, so they can't be made the default.

## Removing Authenticators

`DELETE /user/authenticators/{authenticator}` removes an authenticator. The request fails, though, if what remains would leave the user unable to sign in, or unable to meet the policy (for policies without `ifEnrolled()`). In that case, the error is `keyring::keyring.last_factor`, on `authenticator`.

Recovery codes are only useful while there's a factor to recover, so when a user removes their last extra factor, their recovery codes are removed with it. The policy is checked against what will actually remain.

Removing an [established](#established-authenticators) authenticator is refused while the account's sign-in methods are [frozen](#frozen-sign-in-methods).

Removing an authenticator also stops trusting all of the user's devices. See [Trusted Devices](devices-and-sessions.md#trusted-devices).

An authenticator that failed too many times in a row is refused until it's set up again (see [At the Cap](security.md#at-the-cap)). Removing it clears those failures. So a user in that position signs in another way, removes the authenticator, and adds it back, and the new one starts from nothing. The password is set up again by resetting or changing it.

The password can't be removed this way. It isn't stored in `keyring_authenticators`.

Removing the user's last second factor (the last one beyond recovery codes and email codes) also requires their current password in the request, as `password`. While a second factor sat beside it, their password may have been as short as `min_with_mfa`. On its own, though, NIST SP 800-63B-4 asks for `min_without_mfa` (15 characters, Sec. 3.1.1.2). Keyring only stores a hash, so at this point it checks the length. A missing or wrong password, or one that's too short, gets an error on `password` asking the user to change it first.

## Frozen Sign-In Methods

Signing in counts as a [fresh verification](step-up.md#fresh-verification), so a stolen copy of a session that has just signed in can add a sign-in method of its own. Without anything more, it could then remove the owner's authenticator app, or replace their recovery codes, and the owner couldn't get back in. A password reset leaves sign-in methods alone.

So Keyring freezes an account's sign-in methods for a while, as some large providers do. The account is frozen while either of these is true:

- It has an authenticator that isn't [established](#established-authenticators) yet. That means one added in the last 7 days.
- In the last 7 days, it removed an established authenticator, replaced one, or replaced recovery codes that had codes left.

While it's frozen, these are refused:

- Removing an established authenticator.
- Confirming a factor that allows only one per user, when that replaces an established one. For `recovery`, that's replacing a set that has codes left. Beginning is refused too, so the user isn't shown codes that can't be saved.

The rest still works. The user can add sign-in methods, rename them, and choose the default. They can remove an authenticator that isn't established, and that doesn't freeze anything. So an owner can remove a passkey someone else added, and the account is no longer frozen for it. They can make their first set of recovery codes. A refused change ends no sessions.

A change that goes through and takes something established freezes the account for 7 days from then. That's removing an established authenticator, replacing one, or replacing recovery codes that had codes left.

A refusal is a validation error on `authenticator`. Its message says how long is left, such as `keyring::keyring.frozen_new_authenticator` with "another 3 days". JSON gets a `422` with the usual `message` and `errors`, plus `frozen`. It holds the `reason`, `new-authenticator` or `recent-change`, and `until`, an ISO 8601 time:

```json
{
    "message": "A sign-in method was added recently. To keep your account safe, your other sign-in methods and your recovery codes can't be removed or replaced for another 1 week. The new one can still be removed.",
    "errors": {
        "authenticator": ["A sign-in method was added recently. To keep your account safe, your other sign-in methods and your recovery codes can't be removed or replaced for another 1 week. The new one can still be removed."]
    },
    "frozen": {
        "reason": "new-authenticator",
        "until": "2026-12-04T14:32:45+00:00"
    }
}
```

Keyring throws it as a `Keyring\Exceptions\SignInChangesFrozen`, a `ValidationException` that also has the `freeze`. The refusal dispatches `AuthenticatorRemovalRefused` with the reason `frozen`, or `EnrollmentRefused` with the reason `frozen`. One removal or replacement runs at a time for each user, so two at once can't both find the account unfrozen.

To show it before the user tries, ask `Keyring\Changes\AuthenticatorChanges`. The `frozen` method returns a `Keyring\Changes\Freeze`, with `reason` (a `Keyring\Enums\FreezeReason`) and `until`, or `null`:

```php
use Keyring\Changes\AuthenticatorChanges;

$freeze = app(AuthenticatorChanges::class)->frozen($user);

$freeze?->until;      // a CarbonImmutable
$freeze?->message();  // what the user is told
```

The `authenticator_changes.established_after` option sets the 7 days. See [Configuration](configuration.md#account-changes-and-enrollment). Setting it to `0` turns the freeze off, and with it the protection it gives.

When each account last lost something established is kept in `keyring_sign_in_changes`, one row per user. `keyring:prune` deletes a row once it no longer holds anything back.

### Established Authenticators

An authenticator is established once the account has had it for `authenticator_changes.established_after`. That's 7 days by default, from when it was added (`created_at`). Recovery codes, an emailed code, and the password aren't factors in this sense, so they always count as established.

An authenticator that isn't established works like any other. It signs in, and it can confirm a [fresh verification](step-up.md#fresh-verification). It just doesn't raise the bar yet:

- [`noDowngrade()`](policies.md#no-downgrade) only asks for a passkey or security key once the account has an established one.
- A fresh verification only asks for a key that can't leave its device when that key is established.
- An explicit requirement, such as `aal3()`, `phishingResistant()` or the `keyring:device-bound` middleware, is met by any key that qualifies, new or not. Those come from your app, not from the user's keyring, so a new key can't make them stricter.

`$user->keyring->isEstablished($authenticator)` says whether one is, and `$user->keyring->established()` is the keyring without the ones that aren't.

`keyring:import` keeps when an imported authenticator app or passkey was first confirmed, so one a user has had for a while is established from the start. When Fortify didn't record it, the authenticator counts as added at the import.

### Getting Past the Freeze

Your app's own code, such as a support tool, may need to remove an authenticator or replace recovery codes while the account is frozen. For example, after your support team has checked who they're talking to. Pass `ignoreFreeze: true`:

```php
use Keyring\Changes\AuthenticatorChanges;

app(AuthenticatorChanges::class)->remove($user, $authenticatorId, ignoreFreeze: true);
app(AuthenticatorChanges::class)->add($user, $factor, $authenticator, ignoreFreeze: true);
```

Only do this from code the user can't reach on their own. Keyring's own routes never pass it. The change still freezes the account afterwards, and every other check, such as keeping a way to sign in, still applies.

## Signing Out Other Sessions

A user often adds or removes a sign-in method because someone else is signed in to the account. Confirming an enrollment (including the one that creates new recovery codes) and removing an authenticator both accept an optional boolean, `sign_out_others`. When it's `true` and the change goes through, Keyring signs the user out everywhere except here, in the same way as [`DELETE /user/sessions`](devices-and-sessions.md#listing-and-ending-sessions) does. Every other session is revoked, the "remember me" token is changed, no other device stays trusted, and a pending email change is cancelled. This session carries on under a new ID.

```ts
// confirmEnrollment sends its fields as they are
await confirmEnrollment('totp', enrollment, { code, sign_out_others: true })

// removeAuthenticator takes an option, and sends it as sign_out_others
await removeAuthenticator(id, undefined, { signOutOthers: true })
```

This is off unless the request asks for it, so you may offer it as a checkbox next to the button. Leaving it off costs nothing: adding a new passkey takes nothing away from a session that signed in without it, and a removed authenticator already stops counting in every session it was used in. A password change works the other way round. It [signs other sessions out unless you tell it not to](protected-changes.md#changing-the-password), because everyone who was signed in knew the old password.

A value that isn't a boolean fails with an error on `sign_out_others` before the enrollment is spent. A change that's refused ends no sessions.

## Responses

Every route answers with a [status response](sign-in-flow.md#status-responses). Requests that expect JSON, and that aren't Inertia visits, get JSON with `status`, `message`, and the extra data:

| Action | `status` | Also |
|---|---|---|
| Begin | `enrollment-started` | `factor`, `enrollment` |
| Confirm | `authenticator-added` | `authenticator`, `recoveryCodes`, `continue` when set |
| Update | `authenticator-updated` | `authenticator` |
| Remove | `authenticator-removed` | |

Other requests are redirected back with the `status` flashed to the session. The extra data is flashed too, encrypted, for the next request. Read it with `Keyring::result()`, or read a single key with `Keyring::result('enrollment')`. The [browser package](frontend.md#managing-authenticators) uses the JSON form instead.

## From JavaScript

```ts
import { beginEnrollment, confirmEnrollment, enroll, makeDefault, removeAuthenticator, renameAuthenticator } from '@keyringjs/keyring'

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

For `passkey` and `security-key`, `confirmEnrollment()` runs the browser's WebAuthn ceremony. If a helper fails, it throws a `KeyringRequestError`. That includes the `423` response from step-up. See [Frontend](frontend.md#managing-authenticators).

## From PHP

`$user->keyring`, or `Keyring::for($user)`, gives you a `Keyring\UserKeyring`:

```php
use Keyring\Enums\Category;

$user->keyring->all();                       // every confirmed authenticator, default first, then by priority
$user->keyring->default();                   // the default, or the first stored one
$user->keyring->of('security-key');          // one factor's authenticators
$user->keyring->find($id);
$user->keyring->has(Category::Possession);
$user->keyring->canMeet($requirement);
$user->keyring->canSignIn();                 // can anything start a login?
$user->keyring->isEstablished($authenticator); // has the account had it long enough to count on?
```

Keyring caches the result on the model. If you change authenticators within the same request, call `$user->keyring->refresh()` afterward.

If you need to query rows directly, `$user->authenticators()` is a normal Eloquent relationship. When the model is serialised, secrets, public keys, and credential IDs are hidden. The `secret` attribute is also encrypted at rest.

## Events

The events are in `Keyring\Events`:

| Event | Properties |
|---|---|
| `AuthenticatorAdded` | `user`, `authenticator` |
| `AuthenticatorRemoved` | `user`, `authenticator` |
| `RecoveryCodesGenerated` | `user`, `authenticator` |
| `RecoveryCodeUsed` | `authenticator`, `remaining` |
| `EnrollmentRefused` | `user`, `factor`, `reason` (`invalid`, `not_allowed` or `frozen`) |
| `AuthenticatorRemovalRefused` | `user`, `authenticator`, `reason` (`last_factor` or `frozen`) |
| `AccessRefused` | `user`, `resource`, `id` |

Confirming the `recovery` factor dispatches `RecoveryCodesGenerated` instead of `AuthenticatorAdded`.

The last three events record what was turned away. These are a confirmation whose code or key was wrong (or that came from an account not yet allowed to enroll), a removal that would have left the user unable to sign in, and a request for an authenticator that isn't the user's. Each one still gets the same response: a 422, 403, or 404. Each is also written to the [security log](security-log-and-emails.md#entry-types).
