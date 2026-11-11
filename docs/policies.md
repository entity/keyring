# Policies

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Assurance Levels](#assurance-levels)
- [Only When Enrolled](#only-when-enrolled)
- [Requiring a Second Factor](#requiring-a-second-factor)
- [No Downgrade](#no-downgrade)
- [Deciding Per User and Attempt](#deciding-per-user-and-attempt)
- [How the Policy Is Applied](#how-the-policy-is-applied)
- [Checking Requirements in Code](#checking-requirements-in-code)

## Introduction

The **policy** decides what a user must prove to sign in. You set it once, in your `KeyringServiceProvider`:

```php
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;

Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
```

`keyring:install` adds this line when you pick a second sign-in method. If you never call `Keyring::require()`, the policy is `Requirement::aal2()->ifEnrolled()`, which is how Fortify behaves: a second factor once the user has set one up.

## Requirements

A `Keyring\Login\Requirement` counts **distinct categories** (knowledge, possession, inherence), not verifications. A password plus a PIN is still one factor, and so is a TOTP code plus an email code.

| | Means |
|---|---|
| `Requirement::aal1()` | Any one category. |
| `Requirement::aal2()` | Two categories. |
| `Requirement::aal3()` | Two categories, including possession, and a phishing-resistant key that can't leave its device. |
| `Requirement::factors(3)` | That many categories (at least 1). |
| `Requirement::for(Assurance::AAL2)` | The requirement for an assurance level. |
| `->including(Category::Possession)` | That category must be among those verified. |
| `->phishingResistant()` | At least one verification must be phishing resistant (a passkey or security key). |
| `->deviceBound()` | At least one verification must be a phishing-resistant key that can't leave its device: a security key, or a passkey that doesn't sync. |
| `->ifEnrolled()` | Apply this as far as the user's authenticators can meet it. See [Only When Enrolled](#only-when-enrolled). |
| `->noDowngrade()` | Users with a passkey or security key must use one. See [No Downgrade](#no-downgrade). |

Requirements are immutable. Each modifier returns a new instance, and PHP warns if you discard it:

```php
$requirement = Requirement::aal2()->including(Category::Possession)->phishingResistant();
```

## Assurance Levels

Keyring works out an assurance level from what a user has proved in their session, loosely following NIST SP 800-63B. The levels are `Keyring\Enums\Assurance`: `None`, `AAL1`, `AAL2` and `AAL3`.

| Proved | Level |
|---|---|
| A password | AAL1 |
| A password and a TOTP or recovery code | AAL2 |
| A password and an email code, with [`EmailCode::asSecondFactor()`](factors.md#email-codes) | AAL2 (below NIST's bar) |
| A passkey that syncs (iCloud Keychain, Google Password Manager...) | AAL2 |
| A password and a security key, without user verification | AAL3 |
| A passkey that stays on its device (always user verified) | AAL3 |
| A security key that verified the user (PIN or biometric) | AAL3 |

AAL3 means two categories, one of them a phishing-resistant key that can't leave its device, as NIST SP 800-63B requires. A user-verified passkey proves possession and inherence in one step, so it reaches AAL2 on its own, and AAL3 when it doesn't sync. Whether a key may sync is the backup-eligible flag it reports on every sign in; a key that hasn't reported it counts as synced.

The [step-up middleware](step-up.md#raising-assurance) asks for these levels by name: `keyring:aal2`.

## Only When Enrolled

`ifEnrolled()` applies the requirement as far as the user's authenticators can meet it. When they can't meet all of it, they must prove the strongest version they can, and never just one factor while they have a second.

With `Requirement::aal2()->ifEnrolled()`, a user with only a password signs in with the password. Once they add an authenticator app, they need both.

With `Requirement::aal2()->phishingResistant()->ifEnrolled()`, a user with a password and an authenticator app has no key to meet it, so they still need both. Recovery codes don't count as that second factor: a user with nothing else beyond a password signs in with the password rather than spending a code every time.

Without `ifEnrolled()`, users who can't meet the requirement can't sign in at all. They see an error (`keyring::keyring.unavailable`) on the login page asking them to contact support. Use this only when every account is set up with the factors it needs before it signs in.

## Requiring a Second Factor

`ifEnrolled()` lets users without a second factor carry on with just a password. To make everyone add one (OWASP ASVS 6.3.3 asks for this at level 2), add the `keyring.enrolled` middleware to the routes they must not reach without one, usually the whole app:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: ['keyring.enrolled']);
})
```

It lets guests through, leaving them to `auth`, so it can sit in the `web` group. It also works on a single route or group after `auth`.

```php
// config/keyring.php
'enrollment_url' => '/settings/security',
```

Users still sign in with what they have, then every request under the middleware sends them to `enrollment_url` with the `enroll-first` status until they've set up enough to reach AAL2. JSON requests get a `403` with that status and the URL to send them to. Without an `enrollment_url`, they get a plain `403`.

Recovery codes and email codes don't count, the same as for the [shorter password](configuration.md#passwords). `keyring.enrolled:aal3` asks for a passkey or security key that stays on its device instead.

The enrollment page is always let through, and so are the routes users need to get there and back out: Keyring's own (adding authenticators and confirming), `logout`, email verification and changing the password. Keep anything else the enrollment page calls outside the middleware.

## No Downgrade

`noDowngrade()` stops users with a phishing-resistant authenticator from being talked into a weaker one. When a user has any passkey or security key, the requirement gains `phishingResistant()`, and "try another way" only offers their other passkeys and security keys, plus recovery codes.

Recovery codes stay on offer because they're the way back in when the only key is lost: each one works once, and using one sends a [security email](security-log-and-emails.md) when those are on. A used-up set isn't offered. To refuse them too, and accept only keys:

```php
Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade(except: []));
```

`except` lists factor keys that may stand in for a key, so a custom recovery factor can be added there. An explicit `phishingResistant()` never makes exceptions.

## Deciding Per User and Attempt

Pass a closure to decide for each user and attempt. It receives the user and the `Keyring\Login\Attempt`, and returns a `Requirement`:

```php
use App\Models\User;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;

Keyring::require(fn (User $user, Attempt $attempt) => match (true) {
    $user->is_admin => Requirement::aal2()->phishingResistant(),
    $attempt->device()?->isTrusted() === true => Requirement::aal1(),
    $attempt->risk?->isElevated() === true => Requirement::aal2(),
    default => Requirement::aal2()->ifEnrolled(),
});
```

`ifEnrolled()` and `noDowngrade()` work the same way when a closure returns them.

What the attempt tells you:

| | |
|---|---|
| `$attempt->user()` | The user signing in. |
| `$attempt->device()` | Their known `Keyring\Models\Device` for this browser, or `null` for a new one. A device is trusted when the user ticked "don't ask again on this device" (see [Trusted Devices](devices-and-sessions.md#trusted-devices)). |
| `$attempt->isNewDevice()` | Whether this browser hasn't been seen before. |
| `$attempt->risk` | The `Keyring\Risk\Risk` from the [risk signals](risk.md), or `null`. |
| `$attempt->verifications` | What has been proved so far. |
| `$attempt->remember` | Whether "remember me" was ticked. |
| `$attempt->keyring()` | The user's authenticators. |

The closure must cope with `null` devices and risk, and give its strictest answer for them. Keyring also asks it outside a login, about an attempt nothing is known of (no device, no risk, and `isNewDevice()` false):

- When a user removes an authenticator, to check what's left still meets the policy.
- On every route behind [`keyring.fresh`](step-up.md#fresh-verification), to work out what signing in would ask. There it's asked a second time with the request's device looked up, and the stricter of the two answers stands. Risk is never assessed there, so `$attempt->risk` is `null` both times.

## How the Policy Is Applied

- The policy is asked again after every factor the user verifies during a login. A risk assessment can raise it partway through.
- When the [risk response](risk.md#responding-to-risk) asks for a step-up and the user has enough authenticators, the requirement becomes at least `aal2()`.
- The policy applies to logins, and to [fresh verification](step-up.md#fresh-verification), which asks for as much as a login would. [Step-up](step-up.md) to a level sets its own requirement.
- [Registration](sign-in-flow.md#registration) doesn't sign anyone in by default. Where `registration.reveal_taken` has it sign the new user in, it does so with their password without asking the policy, since they can't have other factors yet.
- Users can't remove an authenticator if what's left can't sign in, or can't meet the policy (unless it uses `ifEnrolled()`). See [Removing Authenticators](authenticators.md#removing-authenticators).

## Checking Requirements in Code

```php
use Keyring\Enums\Category;
use Keyring\Login\Requirement;

$user->keyring->canMeet(Requirement::aal2());   // could their authenticators meet it?
$user->keyring->has(Category::Possession);       // do they have a possession factor?
```

`Keyring::policy($user, $attempt)` returns what the policy says, and `Keyring::requirementFor($user, $attempt)` returns what it comes to once `ifEnrolled()` and `noDowngrade()` are applied.
