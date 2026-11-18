# Risk

- [Introduction](#introduction)
- [Built-in Signals](#built-in-signals)
    - [Telling the User](#telling-the-user)
- [Levels](#levels)
- [Responding to Risk](#responding-to-risk)
- [Actions](#actions)
    - [Requiring a New Password](#requiring-a-new-password)
- [Checkpoints](#checkpoints)
- [Configuring Signals](#configuring-signals)
- [Writing a Signal](#writing-a-signal)
- [Running Risk Yourself](#running-risk-yourself)
- [Using Risk in Your Policy](#using-risk-in-your-policy)
- [Events and Logging](#events-and-logging)

## Introduction

Risk signals look for things that make a sign in or a session look suspicious. Examples include a new device, a new country, or a session cookie turning up in another browser. Each signal that fires adds a score. The scores add up, to a maximum of 100, to a **level**. You decide what to do at each level.

You pick the signals in your `KeyringServiceProvider`. The list that the `keyring:install` Artisan command publishes starts with the signals that make no network call and need nothing your application doesn't already have. Each one is turned on only when the feature it reads from is enabled. With every feature on, the list looks like this:

```php
use Keyring\Risk\Signals;

Keyring::risk()->signals([
    Signals\SessionFingerprintChanged::class,
    // These two read the security log: Features::securityLog().
    Signals\RepeatedFactorFailures::class,
    Signals\SuccessAfterFailures::class,
    // These two go by an account's devices: Features::devices().
    Signals\NewDevice::class,
    Signals\InactiveAccount::class,
    // Signals\RecentlyChangedRecovery::class,
    // Signals\BreachedPassword::class,
    // Signals\NewCountry::class,
    // Signals\ImpossibleTravel::class,
]);
```

With the installer's default features, that means `SessionFingerprintChanged`, `RepeatedFactorFailures`, and `SuccessAfterFailures`. `NewDevice` and `InactiveAccount` are written in as comments until you turn on [`Features::devices()`](devices-and-sessions.md). The other four stay off until you turn them on yourself:

- `BreachedPassword` makes a network call at every sign in. When it finds a user's password in a breach, it [holds that user](#requiring-a-new-password) until they choose another.
- `NewCountry` and `ImpossibleTravel` need a [locator](devices-and-sessions.md#locations). They never fire without one.
- `RecentlyChangedRecovery` needs `Features::emailChanges()`. It's left off because of what the scores add up to, as explained below.

Unless you set your own responses, Keyring responds to what the signals find, [as shown below](#responding-to-risk). The starting set is chosen so that those responses can't keep out a user who has only a password. A step-up asks a user who has a second factor for one, and does nothing to a user who doesn't. The signals that can fire for such a user (`NewDevice`, `InactiveAccount`, and `SuccessAfterFailures`) add up to 75. That's short of the 90 at which a sign in is refused. `RepeatedFactorFailures` only counts failures that follow a correct password, so someone has to know the password to raise it. Adding `RecentlyChangedRecovery`, or raising a score, can take a password-only user past 90. Check the sums whenever you change the list.

If your application doesn't use the published provider, it has no signals until you call `Keyring::risk()->signals([...])`.

## Built-in Signals

The built-in signals live in `Keyring\Risk\Signals`:

| Signal | Fires When | Score | Runs At |
|---|---|---|---|
| `NewDevice` | The browser hasn't signed in before. | 15 | login |
| `NewCountry` | The request comes from a country none of the user's devices have been seen in, and at least one device has a known country. It needs a locator. | 30 | login |
| `ImpossibleTravel` | The last located sign in was 500 km or more away, and getting here since would mean travelling faster than 900 km/h. It needs a locator with coordinates. | 60 | login |
| `RepeatedFactorFailures` | Five or more second factors failed after a correct password in the last 15 minutes (the `within` option). Ten or more doubles the score. | 25 | login |
| `RecentlyChangedRecovery` | The email address changed (or was changed back) within `risk.recent_change` (7 days). | 25 | login |
| `InactiveAccount` | The account last signed in 90 days ago or more (the `after` option), and none of its sessions has been used since. | 30 | login |
| `SuccessAfterFailures` | The first factor was right after five or more failed attempts on the account (the `threshold` option) in the last hour (`within`), counted since it last signed in. | 30 | login |
| `SessionFingerprintChanged` | A signed-in session now comes from a different browser or platform than the one it was last seen in. IP changes alone don't count. | 60 | every request |
| `BreachedPassword` | The password used to sign in appears in a public breach list. It makes a network call at sign in, so the published provider leaves it off. Whatever it scores, Keyring's own response to it [holds the user until they choose a new password](#requiring-a-new-password). | 40 | login |

`SessionFingerprintChanged` compares the session with the browser it was last seen in, and it acts on each change once. A cookie that two browsers use at the same time flips back and forth. So with the default response, the owner is asked to verify again, and emailed, on every switch. To end such a session instead, have [your responder](#actions) answer `Action::reauthenticate()` at `Checkpoint::Request`.

`RepeatedFactorFailures` only counts failures after a correct password. Anyone can type a wrong password for a known email address, and counting those would let a stranger raise the owner's risk. The signal reads the [security log](security-log-and-emails.md) table, so it does nothing when `Features::securityLog()` is off or the table can't be read.

`InactiveAccount` goes by when the account's devices last signed in. It says nothing about an account that has no sign in on record, so turning it on doesn't flag every existing user's next sign in. Devices that go unseen for `devices.keep_unseen_for` (a year) are pruned. After that, a returning user's browser counts as a new device again, which `NewDevice` and the `new_device` email cover.

`SuccessAfterFailures` counts every failed attempt on the account, wrong passwords included. That's what tells a guessed password from a known one. Anyone who knows a username can cause those failures, so the signal can't say whose sign in this is, only that someone has been trying. Its score asks for a second factor and no more. A run of failures is followed once, since the count starts over at each sign in.

### Telling the User

OWASP ASVS 5.0.0 requirement 6.3.5 asks that users hear about a sign in after a long quiet period, or one that follows several failures. On its own, each of these two findings reaches `Level::Medium`. That level asks for a second factor and sends nothing. So Keyring's own response emails the user whenever either finding turns up, whatever the level. The email is the `suspicious_activity` [notice](security-log-and-emails.md#email-types).

A responder of your own replaces Keyring's, this part included. If you want to keep the emails, notify for the two findings yourself:

```php
use Keyring\Risk\Action;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Level;
use Keyring\Risk\Risk;
use Keyring\Risk\Signals\InactiveAccount;
use Keyring\Risk\Signals\SuccessAfterFailures;

Keyring::risk()->respond(function (Risk $risk, Checkpoint $at) {
    $action = match ($risk->level) {
        Level::Low => Action::allow(),
        Level::Medium => Action::stepUp(),
        Level::High => Action::stepUp()->notify(),
        Level::Critical => Action::deny()->revokeAllSessions()->notify(),
    };

    return $risk->has(InactiveAccount::FINDING) || $risk->has(SuccessAfterFailures::FINDING)
        ? $action->notify()
        : $action;
});
```

The email lists what was found, such as "The first sign in for 120 days."

## Levels

The thresholds live under `risk.levels`:

```php
'risk' => [
    'levels' => ['medium' => 30, 'high' => 60, 'critical' => 90],
],
```

A total of 30 or more is `Level::Medium`, 60 or more is `Level::High`, and 90 or more is `Level::Critical`. Anything less is `Level::Low`.

## Responding to Risk

If you don't write your own responder, Keyring takes these actions at every checkpoint:

| Level | Action |
|---|---|
| Low | `Action::allow()` |
| Medium | `Action::stepUp()` |
| High | `Action::stepUp()->notify()` |
| Critical | `Action::deny()->revokeAllSessions()->notify()` |

At login, `revokeAllSessions` is always ignored. A critical login is refused and the `suspicious_activity` email goes out, but the owner stays signed in everywhere else.

Three findings are answered whatever the level. Two of them add a notice, and one adds a hold:

- A sign in that follows several failures (`SuccessAfterFailures`) or a long quiet period (`InactiveAccount`) adds `->notify()` to the action above. See [Telling the User](#telling-the-user).
- When `BreachedPassword` finds the password used to sign in in a breach, `->requirePasswordChange()` is added. See [Requiring a New Password](#requiring-a-new-password).

To set your own, add a responder in your `KeyringServiceProvider`:

```php
use Keyring\Facades\Keyring;
use Keyring\Risk\Action;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Level;
use Keyring\Risk\Risk;
use Keyring\Risk\Signals\ImpossibleTravel;
use Keyring\Risk\Signals\NewCountry;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\SessionFingerprintChanged;

Keyring::risk()->signals([NewDevice::class, NewCountry::class, ImpossibleTravel::class, SessionFingerprintChanged::class])
    ->respond(fn (Risk $risk, Checkpoint $at) => match ($risk->level) {
        Level::Low => Action::allow(),
        Level::Medium => Action::stepUp(),
        Level::High => Action::stepUp()->notify(),
        Level::Critical => Action::deny()->revokeAllSessions()->lockFor('1h')->notify(),
    });
```

The responder receives the `Risk` and where it was assessed, so you can act differently at login and mid-session. To keep the current signals and change only the response, call `Keyring::risk()->respond()` on its own.

The `Risk` object has `score`, `level`, and `findings`. The `findings` value is a list of `Keyring\Risk\Finding` objects, each with `signal`, `score`, and `reason`. It also has `has($signal)`, `reasons()`, and `isElevated()`, which is true for anything above low.

## Actions

To build an action, start with one of the static constructors, then chain any extras you want:

| | At Login | On a Signed-In Request |
|---|---|---|
| `Action::allow()` | Nothing. | Nothing. |
| `Action::stepUp()` | Ask for a second factor, if the user has one (the requirement becomes at least AAL2). | Forget what the session has proved, so step-up middleware asks again. |
| `Action::reauthenticate()` | Nothing. | Sign the session out. |
| `Action::deny()` | Refuse the sign in with the usual "these credentials don't match" error. | Sign the session out. |
| `->revokeAllSessions()` | Nothing, even from your own responder. Otherwise anyone with only the password could sign the owner out whenever they liked. | Sign out every session of the user, including this one. It also changes their "remember me" token, stops trusting their devices, and cancels any pending email change (`Sessions::signOutEverywhere`). |
| `->lockFor('1h')` | Refuse sign ins for that long. Trusted devices stay trusted, for the same reason sessions aren't revoked. | Refuse sign ins for that long, from now, and stop trusting the user's devices. |
| `->notify()` | Send the `suspicious_activity` security email, if it's registered. | The same. |
| `->requirePasswordChange()` | Hold the user until they choose a new password. The sign in goes ahead unless the action also denies it, and the hold is there for whoever signs in next. | Hold them from this request on. |

Locks are kept in the cache store named in `risk.store`. Clearing that store lifts every lock. So if it's your default store, `php artisan cache:clear` lifts them too. Where that matters, give locks a persistent store of their own. A database or Redis store is the one to use. Octane's `octane` store loses every lock when the server restarts, along with [other things](security.md#octanes-cache-store). While a user is locked, every sign in fails with the usual generic error. A "remember me" cookie is signed out instead of being let back in. Sessions that are already signed in carry on. Password reset still works and lifts the lock, so a lock can't keep the owner out for good. Otherwise, a lock lifts on its own when it expires.

### Requiring a New Password

NIST SP 800-63B-4 (Sec. 3.1.1.2) never has passwords changed on a schedule. It always has one changed when there's evidence it was compromised. Stepping up, notifying, and locking don't do that, because the password someone else knows is still the password. `requirePasswordChange` holds the user on your change-password page until the password changes. That makes it the right response for a signal about the password itself.

Keyring's own response does this for `BreachedPassword`. To use it, turn the signal on and tell Keyring where your change-password form is. A user who signs in with a password found in a breach is then held until they choose another:

```php
// app/Providers/KeyringServiceProvider.php
use Keyring\Risk\Signals\BreachedPassword;

Keyring::risk()->push(BreachedPassword::class);

// config/keyring.php
'password_change_url' => '/settings/password',
```

The sign in itself goes ahead as the level says (a second factor, at the signal's own score of 40, when the user has one). The hold is logged as `risk_password_change`. Without a `password_change_url`, a held user gets a `403` on every page, so set it before you turn the signal on.

A responder of your own replaces all of Keyring's response, this part included. To keep it, answer for the finding:

```php
use Keyring\Risk\Signals\BreachedPassword;

Keyring::risk()
    ->push(BreachedPassword::class)
    ->respond(fn (Risk $risk) => match (true) {
        $risk->has(BreachedPassword::FINDING) => Action::stepUp()->requirePasswordChange()->notify(),
        $risk->level === Level::Critical => Action::deny()->revokeAllSessions()->notify(),
        $risk->isElevated() => Action::stepUp(),
        default => Action::allow(),
    });
```

A user with no password is never held, so a responder can ask for this without checking first. See [Requiring a Password Change](protected-changes.md#requiring-a-password-change) for what a held user can reach and how the hold ends.

## Checkpoints

Signals run at one or both of these checkpoints, which come from `Keyring\Risk\Checkpoint`:

- **`Login`**: runs once per login, after the first factor is verified. Every signal that lists it runs.
- **`Request`**: runs on every signed-in request, from the [session middleware](devices-and-sessions.md#the-session-middleware). Only signals that list it run, so keep them cheap. When at least one signal runs at this checkpoint, the responder is called on every request, even at `Level::Low`. A custom responder should return `Action::allow()` for low risk.

When a request-time action does something without signing the session out, such as a step-up, Keyring updates the session's recorded IP and user agent. That way, the same change isn't acted on twice. A step-up also gives the session a new record and revokes the old one. So only the request that noticed the change carries on. An older copy of the session cookie, or a request that was already under way, is signed out instead of keeping what the session had proved.

With [`sessions.end_on_lapse`](devices-and-sessions.md#ending-a-session-with-its-level) turned on, a request-time step-up signs the session out instead, in the same way as `Action::reauthenticate()`. In that setup, a session doesn't outlive what it signed in with.

## Configuring Signals

`Keyring::risk()->signals([...])` replaces the signal list. To keep the signals that are already on and add to them, use `push`:

```php
use Keyring\Risk\Signals\BreachedPassword;

Keyring::risk()->push(BreachedPassword::class, BlocklistedIp::class);
```

Both methods accept class names and instances, so you can change a signal's score:

```php
use Keyring\Risk\Signals\BreachedPassword;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\RepeatedFactorFailures;

Keyring::risk()->signals([
    new NewDevice(score: 20),
    app()->make(RepeatedFactorFailures::class, ['threshold' => 3, 'within' => '1h']),
    BreachedPassword::class,
]);
```

Use `app()->make()` for signals that have dependencies: `RepeatedFactorFailures`, `SuccessAfterFailures`, `InactiveAccount`, `RecentlyChangedRecovery`, and `BreachedPassword`.

These are the constructor options. `within` and `after` are [durations](configuration.md#durations):

| Signal | Options | Defaults |
|---|---|---|
| Every signal | `score` | See the table above. |
| `ImpossibleTravel` | `maxKph`, `minKm` | `900`, `500` |
| `RepeatedFactorFailures` | `threshold`, `within` | `5`, `15m` |
| `SuccessAfterFailures` | `threshold`, `within` | `5`, `1h` |
| `InactiveAccount` | `after` | `90d` |

For example:

```php
use Keyring\Risk\Signals\InactiveAccount;
use Keyring\Risk\Signals\SuccessAfterFailures;

Keyring::risk()->push(
    app()->make(InactiveAccount::class, ['after' => '180d']),
    app()->make(SuccessAfterFailures::class, ['threshold' => 3, 'within' => '24h']),
);
```

## Writing a Signal

To write your own, extend `Keyring\Risk\Signals\Signal` and write the `assess()` method:

```php
namespace App\Keyring;

use Keyring\Risk\Assessment;
use Keyring\Risk\Finding;
use Keyring\Risk\Signals\Signal;

class BlocklistedIp extends Signal
{
    public function assess(Assessment $assessment): ?Finding
    {
        return app(IpBlocklist::class)->contains($assessment->request->ip())
            ? new Finding('blocklisted_ip', 40, 'Signing in from a blocklisted address.')
            : null;
    }
}
```

A signal runs while signing in, unless its `checkpoints()` method says otherwise. To run on every signed-in request instead, return `[Checkpoint::Request]`, and keep those signals cheap. The base class is only a default. Anything that implements `Keyring\Contracts\Signal` works.

The `Assessment` gives you the following:

| | |
|---|---|
| `checkpoint` | Where it's running. |
| `request` | The request. |
| `user` | The user. |
| `attempt` | The login `Attempt`, at the login checkpoint. |
| `session` | The `RegisteredSession`, at the request checkpoint. |
| `location()` | The request's location from the locator, looked up once per request (`Location::of()`). |

Return `null` when nothing's wrong.

## Running Risk Yourself

To assess risk somewhere else, such as in a pipeline step of your own, use the `Keyring\Risk\RiskEngine` that `Keyring::risk()` returns:

```php
use Keyring\Facades\Keyring;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;

$engine = Keyring::risk();
$risk = $engine->assess(new Assessment(Checkpoint::Login, $request, $user, $attempt));
$action = $engine->enforce($user, $risk, Checkpoint::Login);
```

`enforce` asks the responder and carries out the parts that don't depend on where you are. It dispatches `RiskAssessed`, revokes sessions (never at `Checkpoint::Login`), and places the lock. Denying, stepping up, and signing out are up to you, using the returned `Action`. `decide` only asks the responder, and it drops any revocation at login. `signalsFor` returns the signals that run at a given checkpoint.

## Using Risk in Your Policy

At login, Keyring assesses risk before it asks the policy. That means a [policy closure](policies.md#deciding-per-user-and-attempt) can read the result:

```php
Keyring::require(fn (User $user, Attempt $attempt) => $attempt->risk?->has('new_country')
    ? Requirement::aal2()
    : Requirement::aal2()->ifEnrolled());
```

## Events and Logging

When an action does anything, Keyring dispatches a `Keyring\Events\RiskAssessed` event. The event carries `user`, `risk`, `action`, and `checkpoint`. The `checkpoint` is a `Checkpoint` enum value: `Checkpoint::Login` or `Checkpoint::Request`. Keyring logs the event under the strongest thing it did: `risk_denied`, `risk_reauthenticate`, `risk_locked`, `risk_password_change`, `risk_step_up`, `risk_revoked_sessions`, or `risk_notified`. The log entry includes the checkpoint (`login` or `request`), the score, and the reasons.
