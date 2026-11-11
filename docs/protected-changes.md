# Protected Changes

- [Introduction](#introduction)
- [Routes](#routes)
- [Protected Attributes](#protected-attributes)
- [Bypassing Protection](#bypassing-protection)
- [Changing the Email Address](#changing-the-email-address)
    - [Requesting a Change](#requesting-a-change)
    - [Confirming](#confirming)
    - [The Emailed Links](#the-emailed-links)
    - [Reverting](#reverting)
    - [The Old Address Is Reserved](#the-old-address-is-reserved)
    - [Checking and Cancelling](#checking-and-cancelling)
- [Changing the Password](#changing-the-password)
- [Password Rules](#password-rules)
- [Resetting the Password](#resetting-the-password)
- [Email Verification](#email-verification)
- [Events](#events)

## Introduction

Whoever controls the email address and password controls the account. Keyring's flows for changing them check who's asking, tell the owner, and can be undone. Each is a feature:

```php
'features' => [
    Features::resetPasswords(),
    Features::updatePasswords(),
    Features::emailChanges(),
    Features::emailVerification(),
],
```

Once Keyring handles changing the password (`updatePasswords()`) or the email (`emailChanges()`), that attribute is [protected](#protected-attributes): it can only change through Keyring's flow. Without the feature, your app changes it however it likes.

## Routes

| Method | URI | Name | Middleware |
|---|---|---|---|
| `POST` | `/user/email` | `keyring.email.store` | `auth`, `changes_middleware`, limited |
| `GET` | `/user/email` | `keyring.email.show` | `auth` |
| `DELETE` | `/user/email` | `keyring.email.destroy` | `auth` |
| `GET` | `/email-changes/{change}/confirm/{token}` | `keyring.email.confirm` | limited |
| `POST` | `/email-changes/{change}/confirm` | `keyring.email.confirm.store` | limited |
| `GET` | `/email-changes/{change}/revert/{token}` | `keyring.email.revert` | limited |
| `POST` | `/email-changes/{change}/revert` | `keyring.email.revert.store` | limited |
| `PUT` | `/user/password` | `user-password.update` | `auth`, `changes_middleware`, limited |
| `GET` | `/forgot-password` | `password.request` | guest |
| `POST` | `/forgot-password` | `password.email` | guest, limited |
| `GET` | `/reset-password/{token}` | `password.reset` | guest |
| `POST` | `/reset-password` | `password.update` | guest, limited |
| `GET` | `/email/verify` | `verification.notice` | `auth` |
| `GET` | `/email/verify/{id}/{hash}` | `verification.verify` | `auth`, signed, limited |
| `POST` | `/email/verify/{id}/{hash}` | `verification.verify.store` | `auth`, signature in the body, limited |
| `POST` | `/email/verification-notification` | `verification.send` | `auth`, limited |

`auth` here is `auth:{guard}`, Keyring's guard. "Limited" means the `keyring` [rate limiter](configuration.md#pending-logins-timebox-and-rate-limits), 6 a minute by default. The email routes exist only with `Features::emailChanges()`, the password route with `Features::updatePasswords()`, the reset routes with `Features::resetPasswords()`, and the verification routes with `Features::emailVerification()`.

## Protected Attributes

`Features::updatePasswords()` protects `password`, and `Features::emailChanges()` protects `email`. List any others in the `protected` config option:

```php
'protected' => ['phone'],
```

With the `HasKeyring` trait, changing a protected attribute on a user model outside Keyring's flows throws `Keyring\Exceptions\ProtectedAttributeException`:

```php
$user->update(['email' => 'new@example.com']); // throws
```

That includes your own profile forms, so with `Features::emailChanges()` on, take `email` out of them and use the email change flow instead. Setting the attributes when a user is created isn't affected.

The check runs on the model's `updating` event. Changes that skip Eloquent events, such as query builder updates or `saveQuietly()`, aren't caught.

## Bypassing Protection

For trusted admin tooling, such as a support agent fixing an address:

```php
use Keyring\Facades\Keyring;

Keyring::withoutProtection(
    fn () => $user->update(['email' => 'new@example.com']),
    reason: 'Support ticket 42',
);
```

Every use dispatches `Keyring\Events\ProtectionBypassed` with the reason, and logs a `protection_bypassed` entry against the signed-in user who did it (not the user being changed). The callback's return value is returned.

## Changing the Email Address

Whoever controls the address can reset the password, so this flow's safeguards aren't options: the new address always confirms, the old one can always revert for a while, and the old address stays reserved meanwhile. You choose the timings (`email_changes.confirmable_for` and `email_changes.revertable_for`), the validation (your `ValidateEmailChange` action), the emails and the pages.

### Requesting a Change

`POST /user/email` with `email` asks to change the address. It needs a [fresh verification](step-up.md#fresh-verification). Your `ValidatesEmailChanges` action (published to `app/Actions/Keyring/ValidateEmailChange.php`) validates the request and returns the new address, so add rules there, such as only allowing your company's domain. Don't check there whether the address is taken; Keyring handles that without revealing it. The response is always the `email-change-requested` [status response](sign-in-flow.md#status-responses), whatever happens next, so it never reveals whether the new address already has an account.

Keyring then:

1. cancels any change the user already had waiting,
2. stores a pending change with hashed, single-use tokens, valid for `email_changes.confirmable_for` (24 hours by default),
3. emails the **new** address a link to confirm,
4. emails the **current** address a notice with a link to revert, and a link to confirm too when it's needed (see below).

If the new address belongs to another account, everything the account can see is the same: the response, the pending change and the notice to the current address. Only the email to the new address differs. It says someone tried to use the address and carries no link, so the change can never be confirmed and expires like any other. Asking for the current address does nothing.

All of these emails are sent after the response (with Laravel's `defer()`), so how long the request takes doesn't give away which case it was.

A `MustVerifyEmail` user whose address isn't verified yet is refused with `keyring::keyring.verify_email_to_change`: the change would wait on a confirmation from that address, which nobody has shown they can read. Each request mails two addresses, so an account can ask five times an hour (`limits.notices` every `limits.notices_per`), and then gets a `429`. An address someone types is mailed that often at most, whichever accounts ask. Once it has had its share the request is answered the same and stored the same, and nothing more is sent to it.

### Confirming

The new address must always confirm. The current address must confirm too, unless this session proved a possession factor the account has had for `email_changes.established_after` (7 days by default), and since before this session signed in. A newer factor doesn't count, so whoever got in can't add one, use it and skip the check, in the same session or by signing in again with it. Neither does another account's factor, so an impersonated or switched session can't skip it with the admin's.

The change applies once every required confirmation is in. When it applies, Keyring checks the address is still the one the change was requested from, and that no one else has taken the new one in the meantime. If either has changed, the pending change is cancelled. Applying also sets `email_verified_at`, when the model has that attribute loaded, and stops trusting the user's devices.

Applying also signs out the account's other sessions and changes the "remember me" token, as `Sessions::signOutEverywhere()` does. Set `email_changes.sign_out_others` to `false` to keep them; devices stop being trusted either way. The browser that confirmed keeps its session, under a new ID, only if it was signed in as this account. With `email_changed` and `email_change_reverted` on (see [Security Emails](security-log-and-emails.md#email-types)), both addresses are told when the change applies and when an applied change is reverted.

### The Emailed Links

Mail scanners open links on their own. So the emailed links open a page with a button, and only the button changes anything:

- `GET /email-changes/{change}/confirm/{token}` and `.../revert/{token}` render the `email-change` page with `action` (`confirm` or `revert`), `url` (where the button posts) and `token`. They change nothing.
- `POST` to `url` with `token` in the body makes the change.

The link has to carry its token in the URL. The request that acts doesn't, so `url` is `/email-changes/{change}/confirm` or `.../revert` without it, and the token isn't written to access logs and proxies a second time. Post it as a field:

```html
<form method="POST" action="{{ $url }}">
    @csrf
    <input type="hidden" name="token" value="{{ $token }}">
    <button>{{ $action === 'confirm' ? 'Confirm the change' : 'Undo the change' }}</button>
</form>
```

With Inertia, post `{ token }` to `url`. A token that's missing, wrong, used or expired answers with the `email-change-invalid` status.

Links are built from `APP_URL`, never from the request's `Host` header. They work signed out, since they may open in another browser.

After confirming, the user is redirected to `home` (signed in) or the login page, with `status` set to `email-changed` (applied), `email-change-confirmed` (still waiting for the other address) or `email-change-invalid`.

### Reverting

The current address can revert the change while it's pending, and for `email_changes.revertable_for` after it applies (7 days by default). Reverting:

- puts the old address back, even when it was a later change that moved it,
- cancels any later email changes, so links from them can't move the address away again,
- deletes every authenticator that wasn't established when the change was asked for (added within `email_changes.established_after` before it, or since the session that asked signed in), one at a time, dispatching `AuthenticatorRemoved` for each. That can include one the owner added that week, which they can add again,
- signs out every session, and changes the "remember me" token.

The user is then redirected to the forgot password page (or the login page, when password resets are off) with `status` set to `email-change-reverted`, since whoever made the change may also know the password. Reverting doesn't change the password itself.

### The Old Address Is Reserved

While a change can still be reverted, nobody else can take the address it replaced. Otherwise someone who changed the address could register a new account with the old one, and the owner's revert would have nowhere to put it back. That goes for lookalikes too: an address that differs only in case, accents, letter width or characters that don't show is held back with it, because MySQL's and MariaDB's default collations take those for the same address and their unique index would refuse to give it back. Another account asking to move to it gets the same "address in use" email as for any taken address. `Keyring\Rules\UnreservedAddress` refuses it with Laravel's "has already been taken" message, so use it next to `Rule::unique()` wherever users are created. The published `CreateNewUser` action does:

```php
'email' => ['required', 'string', 'email', 'max:255', Rule::unique(User::class), new UnreservedAddress],
```

With the `HasKeyring` trait, saving a user with a reserved address any other way throws `Keyring\Exceptions\ReservedAddressException`, even inside `Keyring::withoutProtection()`. Like [protected attributes](#protected-attributes), the check runs on Eloquent events, so query builder inserts aren't caught. To check an address yourself, use `app(Keyring\Changes\ReservedAddresses::class)->has($address)`. The address is looked up by a keyed hash (`APP_KEY` and `APP_PREVIOUS_KEYS`), since the change stores it encrypted.

### Checking and Cancelling

`GET /user/email` returns the pending change, if any:

```json
{
  "pending": {
    "email": "new@example.com",
    "confirmed": false,
    "needsCurrentConfirmation": true,
    "expiresAt": "2026-11-09T13:00:00+00:00"
  }
}
```

`confirmed` is whether the new address has confirmed. `DELETE /user/email` cancels it and responds with `email-change-cancelled`.

A password reset or a password change cancels any pending change, since whoever knew the old password shouldn't keep a change they started with it. Signing out everywhere else cancels it too, as does anything else that goes through `Sessions::signOutEverywhere()`.

However a change is cancelled, the old address's "this wasn't me" link keeps working until the change would have expired. Whoever asked for the change can cancel it too, and that shouldn't take away the owner's way to remove what was added and sign everything out.

## Changing the Password

`PUT /user/password` needs a [fresh verification](step-up.md#fresh-verification). It passes the request to your `UpdatesUserPasswords` action (published to `app/Actions/Keyring/UpdateUserPassword.php`), which validates it and saves the new password. The published action takes these fields:

| Field | |
|---|---|
| `current_password` | Required when the user has a password. Checked with the `Keyring\Rules\CurrentPassword` rule. |
| `password`, `password_confirmation` | The new password, checked against the [password rules](#password-rules). |

Keyring itself reads `sign_out_others`, an optional boolean that defaults to `true`.

`CurrentPassword` works like Laravel's `current_password` rule, except that a password too long for the stored hash (over 72 bytes for bcrypt, which only reads the first 72) fails like any wrong one. Use it wherever your own code asks for the current password:

```php
use Keyring\Rules\CurrentPassword;

$request->validate(['current_password' => ['required', 'string', new CurrentPassword($request->user())]]);
```

For an action that still uses Laravel's rule, Keyring replaces an over-long `current_password` with a random value before the action sees it.

A user without a password (for example, one who only uses passkeys) can set one with just the fresh verification.

Keyring runs your action as one of its own flows, so it may change the protected `password` attribute, and only that: changing `email` there still throws. The action must save a new password or throw a `ValidationException`; returning without saving throws a `LogicException`, since everything that follows assumes the password changed. Afterwards Keyring regenerates the session ID, destroying the old one, cancels any pending email change, ends any reset links still outstanding and stops trusting the user's devices, including this one. With `sign_out_others` on, it also revokes every other session and changes the "remember me" token. The response is the `password-updated` [status response](sign-in-flow.md#status-responses).

## Password Rules

`Keyring\Support\PasswordRules::for($user)` returns validation rules that follow OWASP's guidance:

- at least `min_with_mfa` characters (8) when the user has a second factor, and `min_without_mfa` (15) when they don't, where "a second factor" means their authenticators could meet AAL2 including possession without recovery codes (a fallback) or email codes (below NIST AAL2). Removing the last one takes the password typed again, so Keyring can check it's long enough on its own (see [Removing Authenticators](authenticators.md#removing-authenticators)),
- at most `max` characters (128),
- no composition rules by default (no "one uppercase, one symbol"),
- breached passwords rejected, in production by default (Laravel lets them through when Have I Been Pwned can't be reached),
- the most common passwords rejected always, from a list bundled with Keyring (the long-enough entries of SecLists' 10,000 most common, MIT licensed),
- no passwords containing the site's name, or the user's name or email username (words of four characters or more),
- with bcrypt, passwords over 72 bytes are rejected, because bcrypt silently ignores the rest,
- and `confirmed`, so the request needs `password_confirmation`.

`PasswordRules::for()` with no user applies the stricter, no-MFA minimum, which is what registration uses. At registration there's no user to take a name from, so pass the words yourself, as the published `CreateNewUser` does: `PasswordRules::for(context: [$input['name'], $input['email']])`.

The published actions all take their rules from one trait, `app/Actions/Keyring/PasswordValidationRules.php`, so that's the place to change them. To add to Keyring's rule, pass a callback that receives the `Illuminate\Validation\Rules\Password` rule (with its length already set for the user) and returns it:

```php
use Illuminate\Validation\Rules\Password;

protected function passwordRules((Authenticatable&Model)|null $user = null, array $context = []): array
{
    return PasswordRules::for($user, fn (Password $rule) => $user?->is_admin ? $rule->mixedCase()->symbols() : $rule, $context);
}
```

## Resetting the Password

`POST /forgot-password` with `email` sends a reset link when the address has an account. The answer is the same either way: the `reset-link-sent` [status response](sign-in-flow.md#status-responses). The email is sent after the response, so timing doesn't give it away either.

The email is Laravel's own `Illuminate\Auth\Notifications\ResetPassword`, sent through your user model's `sendPasswordResetNotification()`, so you change it the usual Laravel way. Keyring sets its link with `ResetPassword::createUrlUsing()`, built from `APP_URL`, never the `Host` header. If you've already set `createUrlUsing()` yourself, Keyring leaves it alone. The reset page is sent with `Referrer-Policy: no-referrer`, so the token in its URL doesn't reach anything the page loads through the referrer.

`POST /reset-password` takes `token`, `email`, `password` and `password_confirmation`. A bad token, or an address without an account, always gets the same error on `email`. Only once the token is accepted does Keyring pass the request to your `ResetsUserPasswords` action (published to `app/Actions/Keyring/ResetUserPassword.php`), which checks the password rules and saves the password, so the form doesn't reveal which addresses have accounts or MFA. As with changes, the action may only change the password, and must save one or throw. Then Keyring:

- revokes every session and changes the "remember me" token,
- cancels any pending email change,
- lifts any [risk lock](risk.md#actions) on the account,
- clears the account's sign-in lockouts and failure counts, the in-a-row ones too, on the factors that can start a sign in, and logs that it did. Second factors keep theirs. Per-IP limits stay,
- dispatches `Keyring\Events\PasswordReset`, and Laravel's `Illuminate\Auth\Events\PasswordReset`,
- redirects to the login page with the `password-reset` status. It never signs the user in, so the policy still applies at their next login.

Resets use Laravel's password broker (`passwords.broker`, or your default), so its token expiry and throttling apply. A reset link stops working as soon as the password changes through Keyring, the account's email address changes, or the user is deleted. Password reset keeps working while an account is locked, and lifts the lock, so a lock can't keep the owner out for good.

## Email Verification

With `Features::emailVerification()` on, Keyring provides Laravel's verification routes, the `verify-email` page that asks the user to check their inbox, and the `email-verification` page the emailed link opens. Verification links are built from `APP_URL` and signed over the path only (`signed:relative`), so a forged `Host` header can't redirect them.

Laravel verifies the address as soon as the link is opened. Keyring doesn't: like its other emailed links, the link opens a page with a button, and only the button changes anything. So nothing that fetches the link by itself verifies an address, and no `GET` in Keyring changes state.

- `GET /email/verify/{id}/{hash}` renders the `email-verification` page with `email` (the address being verified), `url`, `expires` and `signature`. It changes nothing. Someone already verified is sent on to `home`.
- `POST` to `url` with `expires` and `signature` in the body verifies the address. `url` is the link's path without its query string, so the signature isn't in the URL of the request that acts.

```html
<form method="POST" action="{{ $url }}">
    @csrf
    <input type="hidden" name="expires" value="{{ $expires }}">
    <input type="hidden" name="signature" value="{{ $signature }}">
    <button>Verify {{ $email }}</button>
</form>
```

Both need the user to be signed in, as the account the link was sent to: anyone else gets a `403`, and a signed-out browser goes to the login page and comes back. The link stops working when it expires (`auth.verification.expire`, 60 minutes) or the account's address changes. After verifying, users go to `home` with `?verified=1`, and Laravel's `Illuminate\Auth\Events\Verified` event is dispatched as usual.

Laravel's own `VerifyEmail` notification and the `MustVerifyEmail` contract work unchanged. Only what the link's `GET` does is different.

If you've already set `VerifyEmail::createUrlUsing()` yourself, Keyring leaves it alone.

## Events

In `Keyring\Events`:

| Event | Properties |
|---|---|
| `EmailChangeRequested` | `user`, `change` |
| `EmailChanged` | `user`, `change` |
| `EmailChangeReverted` | `user`, `change` |
| `PasswordChanged` | `user` |
| `PasswordReset` | `user` |
| `ProtectionBypassed` | `reason` |

`change` is a `Keyring\Models\PendingChange`. Its tokens and addresses are hidden from serialisation, and the addresses are encrypted at rest.

Keyring also dispatches Laravel's `Illuminate\Auth\Events\PasswordReset` alongside its own `PasswordReset`, so listeners for either work.
