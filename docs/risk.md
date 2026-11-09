# Risk

- [Introduction](#introduction)
- [Built-in Signals](#built-in-signals)
- [Levels](#levels)
- [Responding to Risk](#responding-to-risk)
- [Actions](#actions)
- [Checkpoints](#checkpoints)
- [Configuring Signals](#configuring-signals)
- [Writing a Signal](#writing-a-signal)
- [Running Risk Yourself](#running-risk-yourself)
- [Using Risk in Your Policy](#using-risk-in-your-policy)
- [Events and Logging](#events-and-logging)

## Introduction

Risk signals look for things that make a sign in or session suspicious: a new device, a new country, a session cookie turning up in another browser. Each signal that fires adds a score. The scores add up (capped at 100) to a **level**, and you decide what to do at each level.

Risk is off until you pick signals in your `KeyringServiceProvider`:

```php
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\SessionFingerprintChanged;

Keyring::risk([NewDevice::class, SessionFingerprintChanged::class]);
```

Once signals are picked, Keyring responds to them as shown below unless you set your own responses. Without a [locator](devices-and-sessions.md#locations), the location signals never fire. The device signals need [`Features::devices()`](devices-and-sessions.md), and `RepeatedFactorFailures` needs [`Features::securityLog()`](security-log-and-emails.md).

## Built-in Signals

In `Keyring\Risk\Signals`:

| Signal | Fires when | Score | Runs at |
|---|---|---|---|
| `NewDevice` | The browser hasn't signed in before. | 15 | login |
| `NewCountry` | The request comes from a country none of the user's devices have been seen in, and at least one device has a known country. Needs a locator. | 30 | login |
| `ImpossibleTravel` | The last located sign in was 500 km or more away, and getting here since would mean travelling faster than 900 km/h. Needs a locator with coordinates. | 60 | login |
| `RepeatedFactorFailures` | Five or more second factors failed after a correct password in the last 15 minutes (the `within` option). Ten or more doubles the score. | 25 | login |
| `RecentlyChangedRecovery` | The email address changed (or was changed back) within `risk.recent_change` (7 days). | 25 | login |
| `SessionFingerprintChanged` | A signed-in session now comes from a different browser or platform than the one that signed in. IP changes alone don't count. | 60 | every request |
| `BreachedPassword` | The password just used appears in a public breach list. Not on by default: it makes a network call at sign in. | 40 | login |

`RepeatedFactorFailures` only counts failures after a correct password. Anyone can type a wrong password for a known email, so counting those would let a stranger raise the owner's risk. It reads the [security log](security-log-and-emails.md), so it does nothing when the log is off.

## Levels

```php
'risk' => [
    'levels' => ['medium' => 30, 'high' => 60, 'critical' => 90],
],
```

A total of 30 or more is `Level::Medium`, 60 or more `Level::High`, 90 or more `Level::Critical`, and anything less `Level::Low`.

## Responding to Risk

Without your own responder, Keyring does this at every checkpoint:

| Level | Action |
|---|---|
| Low | `Action::allow()` |
| Medium | `Action::stepUp()` |
| High | `Action::stepUp()->notify()` |
| Critical | `Action::deny()->revokeAllSessions()->notify()` |

At login, `revokeAllSessions()` is always ignored: a critical login is refused and the `suspicious_activity` email goes out if it's turned on, but the owner stays signed in everywhere else.

Set your own in `KeyringServiceProvider`:

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

Keyring::risk([NewDevice::class, NewCountry::class, ImpossibleTravel::class, SessionFingerprintChanged::class])
    ->respond(fn (Risk $risk, Checkpoint $at) => match ($risk->level) {
        Level::Low => Action::allow(),
        Level::Medium => Action::stepUp(),
        Level::High => Action::stepUp()->notify(),
        Level::Critical => Action::deny()->revokeAllSessions()->lockFor('1h')->notify(),
    });
```

The responder gets the `Risk` and where it was assessed, so you can act differently at login and mid-session. `Keyring::risk()` with no arguments keeps the current signals, so you can call `->respond()` alone.

`Risk` has `score`, `level`, `findings` (a list of `Keyring\Risk\Finding` with `signal`, `score` and `reason`), `has($signal)`, `reasons()` and `isElevated()` (anything above low).

## Actions

Build an action with one of the static constructors and chain extras:

| | At login | On a signed-in request |
|---|---|---|
| `Action::allow()` | Nothing. | Nothing. |
| `Action::stepUp()` | Ask for a second factor, if the user has one (the requirement becomes at least AAL2). | Forget what the session has proved, so step-up middleware asks again. |
| `Action::reauthenticate()` | Nothing. | Sign the session out. |
| `Action::deny()` | Refuse the sign in with the usual "these credentials don't match" error. | Sign the session out. |
| `->revokeAllSessions()` | Nothing, even from your own responder. Otherwise anyone with only the password could sign the owner out whenever they liked. | Sign out every session of the user, including this one, change their "remember me" token, stop trusting their devices and cancel any pending email change (`Sessions::revokeAll()`). |
| `->lockFor('1h')` | Refuse sign ins for that long. | The same, from now. |
| `->notify()` | Send the `suspicious_activity` security email, if it's turned on. | The same. |

Locks are kept in the cache store named in `risk.store`. While locked, every sign in fails with the usual generic error, and a "remember me" cookie is signed out instead of let back in. Sessions that are already signed in carry on. Password reset still works and lifts the lock, so a lock can't keep the owner out for good. Otherwise a lock lifts on its own when it expires.

## Checkpoints

Signals run at one or both checkpoints (`Keyring\Risk\Checkpoint`):

- **`Login`**: once per login, after the first factor is verified. All signals that list it run.
- **`Request`**: on every signed-in request, from the [session middleware](devices-and-sessions.md#the-session-middleware). Only signals that list it run, so keep them cheap. When at least one signal runs at this checkpoint, the responder is called on every request, even at `Level::Low`, so a custom responder should return `Action::allow()` for low risk.

When a request-time action does something without signing the session out (a step-up, say), Keyring updates the session's recorded IP and user agent, so the same change isn't acted on twice.

## Configuring Signals

`Keyring::risk([...])` replaces the signal list. To keep the defaults and add to them, use `push()`:

```php
use Keyring\Risk\Signals\BreachedPassword;

Keyring::risk()->push(BreachedPassword::class, BlocklistedIp::class);
```

Both accept class names and instances, so you can change a signal's score:

```php
use Keyring\Risk\Signals\BreachedPassword;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\RepeatedFactorFailures;

Keyring::risk([
    new NewDevice(score: 20),
    app()->make(RepeatedFactorFailures::class, ['threshold' => 3, 'within' => '1h']),
    BreachedPassword::class,
]);
```

Use `app()->make()` for signals with dependencies (`RepeatedFactorFailures`, `RecentlyChangedRecovery`, `BreachedPassword`).

The constructor options are: `score` on every signal, `maxKph` and `minKm` on `ImpossibleTravel`, and `threshold` and `within` (a [duration](configuration.md#durations), `15m` by default) on `RepeatedFactorFailures`.

## Writing a Signal

Implement `Keyring\Contracts\Signal`:

```php
namespace App\Keyring;

use Keyring\Contracts\Signal;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;

class BlocklistedIp implements Signal
{
    public function assess(Assessment $assessment): ?Finding
    {
        return app(IpBlocklist::class)->contains($assessment->request->ip())
            ? new Finding('blocklisted_ip', 40, 'Signing in from a blocklisted address.')
            : null;
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}
```

The `Assessment` gives you:

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

To assess risk somewhere else, such as a pipeline step of your own, use the `Keyring\Risk\RiskEngine` that `Keyring::risk()` returns:

```php
use Keyring\Facades\Keyring;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;

$engine = Keyring::risk();
$risk = $engine->assess(new Assessment(Checkpoint::Login, $request, $user, $attempt));
$action = $engine->enforce($user, $risk, Checkpoint::Login);
```

`enforce()` asks the responder and carries out the parts that don't depend on where you are: it dispatches `RiskAssessed`, revokes sessions (never at `Checkpoint::Login`) and places the lock. Denying, stepping up and signing out are up to you, from the returned `Action`. `decide()` only asks the responder, dropping any revocation at login, and `signalsFor($checkpoint)` returns the signals that run at a checkpoint.

## Using Risk in Your Policy

At login, risk is assessed before the policy is asked, so a [policy closure](policies.md#deciding-per-user-and-attempt) can read it:

```php
Keyring::require(fn (User $user, Attempt $attempt) => $attempt->risk?->has('new_country')
    ? Requirement::aal2()
    : Requirement::aal2()->ifEnrolled());
```

## Events and Logging

When an action does anything, Keyring dispatches `Keyring\Events\RiskAssessed` with `user`, `risk`, `action` and `checkpoint` (the `Checkpoint` enum, `Checkpoint::Login` or `Checkpoint::Request`), and logs it as `risk_denied`, `risk_reauthenticate`, `risk_step_up`, `risk_revoked_sessions` or `risk_notified`, with the checkpoint (`login` or `request`), score and reasons.
