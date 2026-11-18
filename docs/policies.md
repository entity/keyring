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

The `keyring:install` command adds this line when you pick a second sign-in method. If you never call `Keyring::require`, the policy is `Requirement::aal2()->ifEnrolled()`. That means a user signs in with the password alone until they set up a second factor. From then on, they need that factor too.

## Requirements

A `Keyring\Login\Requirement` counts **distinct categories**, not verifications. The three categories that count as authentication factors are knowledge, possession, and inherence. A password plus a PIN is still one factor, and so is a TOTP code plus a recovery code. An [email code](factors.md#email-codes) belongs to a fourth category, `Category::Address`, which isn't an authentication factor. It never counts as a factor, and it only counts as a step where steps are asked for.

| | Means |
|---|---|
| `Requirement::aal1()` | Any one category. |
| `Requirement::aal2()` | Two categories, one of them possession. See [Assurance Levels](#assurance-levels). |
| `Requirement::aal3()` | Two categories, from an attested, phishing-resistant key that can't leave its device, by itself or with a password. See [Assurance Levels](#assurance-levels). |
| `Requirement::factors(3)` | That many categories of any kind, and at least 1. `factors(2)` means two categories without asking which ones, so it asks for less than `aal2()`. |
| `Requirement::steps(2)` | That many categories of any kind, with at least one of them a factor. A password and an email code will do. |
| `Requirement::for(Assurance::AAL2)` | The requirement for a given assurance level. |
| `->including(Category::Possession)` | That category must be among the ones verified. |
| `->phishingResistant()` | At least one verification must be phishing resistant (a passkey or security key). |
| `->deviceBound()` | At least one verification must be a phishing-resistant key that can't leave its device: a security key, or a passkey that doesn't sync. That's what the key reports about itself, with or without attestation. |
| `->attestedKey()` | That key must also have been added with a [verified attestation](passkeys.md#requiring-attestation). Only that key, and factors the user doesn't hold (such as a password), are counted. `aal3()` is `aal2()` with this added. |
| `->ifEnrolled()` | Apply this as far as the user's authenticators can meet it. See [Only When Enrolled](#only-when-enrolled). |
| `->noDowngrade()` | Users with a passkey or security key must use one. See [No Downgrade](#no-downgrade). |

Requirements are immutable. Each modifier returns a new instance, and PHP warns you if you discard the result:

```php
$requirement = Requirement::aal2()->including(Category::Knowledge)->phishingResistant();
```

## Assurance Levels

Keyring works out an assurance level from what a user has proved in their session. The levels follow NIST SP 800-63B-4 as far as a library can check. That covers which kinds of factor were proved, by what, and when. The levels are the cases of `Keyring\Enums\Assurance`: `None`, `AAL1`, `AAL2`, and `AAL3`.

| Proved | Level |
|---|---|
| A password | AAL1 |
| A password and an email code, with [`EmailCode::asExtraStep()`](factors.md#email-codes) | AAL1: NIST doesn't accept email as an authenticator |
| A password and a TOTP or recovery code | AAL2 |
| A passkey that syncs (iCloud Keychain, Google Password Manager...) | AAL2 |
| A passkey or security key that stays on its device, added without attestation, alone or with a password | AAL2 |
| A synced passkey that verified the user, and an attested security key that was only touched | AAL2 |
| A password and an attested security key, without user verification | AAL3 |
| An attested security key or passkey that stays on its device and verified the user (PIN or biometric) | AAL3 |

A user-verified passkey proves possession and inherence in one step, so it reaches AAL2 on its own.

AAL2 means two categories, one of which is possession, which is something the user has. NIST SP 800-63B-4 (Sec. 2.2.1) accepts a password or a biometric only together with a physical authenticator. It never accepts a biometric by itself (Sec. 3.2.3). Every factor Keyring ships fits this rule. Inherence only ever comes from a passkey or security key that verified the user, and that is possession too. This matters for [a factor of your own](factors.md#categories). A factor that reports `Knowledge` and `Inherence`, or `Inherence` alone, leaves a session at AAL1, however it's combined with a password.

AAL3 is narrower than "two factors with a hardware key". NIST asks for a key that can't be exported, along with a second factor that's either the key's own activation or a password (Sec. 2.3.1 and 2.3.2). So Keyring needs all of the following:

- The key is phishing resistant, and it reports that it can't sync. Keyring reads that from the backup-eligible flag on every sign in. A key that hasn't reported the flag counts as synced.
- Something has to vouch for that report. A key's flags are only what the key says about itself, and software can say the same. The key has to belong to a factor set up with [`requireAttestation()`](passkeys.md#requiring-attestation), and it has to have been added with an attestation that chained to a root you trust.
- The second factor is either that key's own user verification or a password. What another authenticator proved doesn't count. A synced passkey that verified the user on whatever device it had reached says nothing about who touched the security key.

Without attestation, no session reaches AAL3, and `keyring:aal3` sends users to your enrollment page. You can still ask for a phishing-resistant key that stays on its device, which is worth having on its own. Use `Requirement::aal2()->deviceBound()` in a policy, or [`keyring:aal2,device-bound`](step-up.md#raising-assurance) on a route. Those sessions are AAL2.

A session that Keyring calls AAL3 has met what NIST asks of the authentication itself. NIST's AAL3 also needs authenticators and verifier cryptography validated to FIPS 140, and no library can supply that. Before you tell anyone your application is AAL3, you'll need to buy validated keys, limit the factor to those models with [`allowOnly()`](passkeys.md#allowing-only-certain-models), and run PHP on a validated cryptographic module.

The [step-up middleware](step-up.md#raising-assurance) asks for these levels by name, as in `keyring:aal2`.

## Only When Enrolled

`ifEnrolled()` applies the requirement as far as the user's authenticators can meet it. When they can't meet all of it, they must prove the strongest version they can. They never get away with one factor while they have a second.

With `Requirement::aal2()->ifEnrolled()`, a user with only a password signs in with the password. Once they add an authenticator app, they need both.

With `Requirement::aal2()->phishingResistant()->ifEnrolled()`, a user with a password and an authenticator app has no key to meet it, so they still need both. Recovery codes don't count as that second factor. A user with nothing beyond a password signs in with the password, rather than spending a code every time.

A user whose only other sign-in method is an [email code](factors.md#email-codes) can't give a second factor either, so they're asked for the step they do have: the password and the emailed code. That session is AAL1. Once they add a real second factor, the emailed code stops being asked for or offered.

Without `ifEnrolled()`, users who can't meet the requirement can't sign in at all. That includes a user with a password and an email code under `Requirement::aal2()`. If a password and an emailed code should be enough to sign in, use `Requirement::steps(2)` instead. Users in that situation see an error (`keyring::keyring.unavailable`) on the login page, asking them to contact support. Only leave out `ifEnrolled()` when every account is set up with the factors it needs before it signs in.

## Requiring a Second Factor

`ifEnrolled()` lets users without a second factor carry on with only a password. To make everyone add one (OWASP ASVS 5.0.0 asks for this at Level 2, in requirement 6.3.3), add the `keyring.enrolled` middleware to the routes that users shouldn't reach without one. Usually that's the whole app:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->web(append: ['keyring.enrolled']);
})
```

It lets guests through and leaves them to `auth`, so you can add it to the `web` group. It also works on a single route or group, placed after `auth`.

When you pick an authenticator app, passkeys, or security keys, the `keyring:install` command asks "Require a second factor for everyone?" The answer is yes unless you say otherwise. The command then adds the middleware to the `web` group in your `KeyringServiceProvider`. That does the same as the lines above:

```php
// app/Providers/KeyringServiceProvider.php
use Illuminate\Contracts\Http\Kernel;

$this->app->make(Kernel::class)->appendMiddlewareToGroup('web', 'keyring.enrolled');
```

The installer doesn't ask when the password is the only sign-in method, or when the only other one is an emailed code. In those cases, nobody could set up what the middleware asks for, and every page would send them to a page that can't help.

Users are sent to the page at `enrollment_url` in your `config/keyring.php` configuration file. The installer sets it to:

```php
// config/keyring.php
'enrollment_url' => '/settings/security',
```

Users still sign in with what they have. After that, every request under the middleware sends them to `enrollment_url` with the `enroll-first` status, until they've set up enough to reach AAL2. JSON requests get a `403` response with that status and the URL to send them to. Without an `enrollment_url`, they get a plain `403`.

Recovery codes don't count, and neither do email codes, because they aren't a factor. A user who signs in with a password and an emailed code is sent to add a real one. The same rule decides which accounts may use the [shorter minimum password length](configuration.md#passwords). To ask for an attested key that stays on its device instead, use `keyring.enrolled:aal3`. For a key that stays on its device, attested or not, use `keyring.enrolled:aal2,device-bound`.

The enrollment page is always let through, and so are the routes users need to get there and back out. Those are Keyring's own (adding authenticators and confirming), `logout`, email verification, and changing the password. Keep anything else that the enrollment page calls outside the middleware.

## No Downgrade

`noDowngrade()` stops users with a phishing-resistant authenticator from being talked into a weaker one. When a user has any passkey or security key, the requirement gains `phishingResistant()`. "Try another way" then offers only their other passkeys and security keys, plus recovery codes.

Recovery codes stay on offer, because they're the way back in when the only key is lost. Each one works once, and using one sends a [security email](security-log-and-emails.md) when those emails are turned on. A used-up set isn't offered. If you want to refuse codes too, and accept only keys, use:

```php
Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade(except: []));
```

The `except` argument lists factor keys that may stand in for a key, so you can add a custom recovery factor there. An explicit `phishingResistant()` never makes exceptions.

## Deciding Per User and Attempt

You may pass a closure to decide the requirement for each user and attempt. It receives the user and the `Keyring\Login\Attempt`, and it returns a `Requirement`:

```php
use App\Models\User;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;

Keyring::require(fn (User $user, Attempt $attempt) => match (true) {
    $user->is_admin => Requirement::aal2()->phishingResistant(),
    $attempt->device()?->isTrusted() === true => Requirement::aal1(),
    $attempt->risk?->isElevated() === true => Requirement::aal2(),
    // An unknown device and risk land here, so keep this the strictest
    // answer you want for an attempt Keyring knows nothing about.
    default => Requirement::aal2()->ifEnrolled(),
});
```

`ifEnrolled()` and `noDowngrade()` work the same way when a closure returns them.

The attempt tells you the following:

| | |
|---|---|
| `$attempt->user()` | The user signing in. |
| `$attempt->device()` | Their known `Keyring\Models\Device` for this browser, or `null` for a new one. A device is trusted when the user ticked "don't ask again on this device" (see [Trusted Devices](devices-and-sessions.md#trusted-devices)). |
| `$attempt->isNewDevice()` | Whether this browser hasn't been seen before. |
| `$attempt->risk` | The `Keyring\Risk\Risk` from the [risk signals](risk.md), or `null`. |
| `$attempt->verifications` | What has been proved so far. |
| `$attempt->remember` | Whether "remember me" was ticked. |
| `$attempt->keyring()` | The user's authenticators. |

Your closure must cope with `null` devices and risk, and give its strictest answer for them. Keyring also calls it outside a sign in, for an attempt that nothing is known about (no device, no risk, and `isNewDevice()` false):

- When a user removes an authenticator, to check that what's left still meets the policy.
- On every route behind [`keyring.fresh`](step-up.md#fresh-verification), to work out what signing in would ask. There, the closure is asked a second time, with the request's device looked up, and the stricter of the two answers stands. Risk is never assessed there, so `$attempt->risk` is `null` both times. The policy can only add to what that route asks. Its floor is the strongest combination the account can give.

## How the Policy Is Applied

- The policy is asked again after every factor the user verifies during a sign in. A risk assessment can raise it partway through.
- When the [risk response](risk.md#responding-to-risk) asks for a step-up and the user has enough authenticators, the requirement becomes at least `aal2()`.
- The policy applies to sign ins, and to [fresh verification](step-up.md#fresh-verification). Fresh verification asks for as much as a sign in would, and never less than the strongest combination the account can give. [Step-up](step-up.md) to a level sets its own requirement.
- [Registration](sign-in-flow.md#registration) doesn't sign anyone in by default. If `registration.reveal_taken` makes it sign the new user in, it does so with their password and doesn't ask the policy, since they can't have other factors yet.
- Users can't remove an authenticator if what's left can't sign in, or can't meet the policy, unless the policy uses `ifEnrolled()`. See [Removing Authenticators](authenticators.md#removing-authenticators).

## Checking Requirements in Code

You may check a user against a requirement from anywhere in your code:

```php
use Keyring\Enums\Category;
use Keyring\Login\Requirement;

$user->keyring->canMeet(Requirement::aal2());   // could their authenticators meet it?
$user->keyring->has(Category::Possession);       // do they have a possession factor?
```

The `Keyring::policy` method returns what the policy says. The `Keyring::requirementFor` method returns what that comes to once `ifEnrolled()` and `noDowngrade()` are applied.
