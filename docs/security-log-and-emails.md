# Security Log & Emails

- [The Security Log](#the-security-log)
    - [Entry Types](#entry-types)
    - [Showing Recent Activity](#showing-recent-activity)
    - [Pruning](#pruning)
- ["Was This You?" Alerts](#was-this-you-alerts)
- [Security Emails](#security-emails)
    - [Email Types](#email-types)
    - [Customising the Copy](#customising-the-copy)
    - [Emails Keyring Always Sends](#emails-keyring-always-sends)

## The Security Log

Keyring records sign ins, failures, lockouts, changes and automatic actions in the `keyring_events` table, as `Keyring\Models\SecurityEvent` rows. Each entry has a `type`, the user (when known), the `factor`, the `device_id`, the IP address, the user agent, `meta` and `created_at`.

The log never holds passwords, codes, tokens or session IDs.

```php
'events' => [
    'enabled' => true,
    'keep_for' => '180d',
],
```

Set `enabled` to `false` to stop logging. "Was this you?" alerts and the `RepeatedFactorFailures` risk signal read from the log, so they stop working too.

### Entry Types

| Type | When | `meta` |
|---|---|---|
| `signed_in` | A login completed. | `factors` |
| `confirmed` | A step-up completed. | `factors` |
| `factor_failed` | A factor failed. | |
| `second_factor_failed` | A factor failed during a login after a correct password. | |
| `locked_out` | A rate limit was hit. Not linked to a user. | `retry_after` |
| `signed_out` | The user signed out. | |
| `authenticator_added`, `authenticator_removed` | | `name` |
| `recovery_codes_generated` | | |
| `recovery_code_used` | | `remaining` |
| `new_device` | A sign in from a new device. | `device` |
| `device_revoked` | A device was signed out. | `device` |
| `device_reported` | A device was signed out from the "this wasn't me" link. | `device` |
| `sessions_revoked` | "Sign out everywhere else". | `count` |
| `email_change_requested`, `email_changed`, `email_change_reverted` | | |
| `password_changed`, `password_reset` | | |
| `protection_bypassed` | `Keyring::withoutProtection()` was used. Linked to the signed-in user who did it. | `reason` |
| `clone_suspected` | A passkey or security key's counter went backwards. | `name` |
| `risk_denied`, `risk_reauthenticate`, `risk_step_up`, `risk_revoked_sessions`, `risk_notified` | A risk action did something. | `checkpoint`, `score`, `reasons` |

A wrong password for an unknown account is logged as `factor_failed` with no user.

### Showing Recent Activity

`Keyring::activity($user, $limit = 25)` returns the user's most recent entries, newest first, for a settings page:

```php
use Keyring\Facades\Keyring;

return Inertia::render('settings/security', [
    'activity' => Keyring::activity($request->user())->map(fn ($event) => [
        'type' => $event->type,
        'factor' => $event->factor,
        'ip' => $event->ip,
        'at' => $event->created_at->toIso8601String(),
    ]),
]);
```

### Pruning

`SecurityEvent` is mass prunable: entries older than `events.keep_for` (180 days) are deleted by Laravel's `model:prune` command. That command only finds models in `app/Models` by default, so name Keyring's model:

```php
use Illuminate\Support\Facades\Schedule;
use Keyring\Models\SecurityEvent;

Schedule::command('model:prune', ['--model' => [SecurityEvent::class]])->daily();
```

## "Was This You?" Alerts

After a successful sign in, Keyring flashes `keyring.alerts` to the session: a list of log entries worth asking the user about, which they haven't seen yet. Each one is shown once.

```json
[
  { "type": "second_factor_failed", "factor": "totp", "at": "2026-11-08T09:12:00+00:00", "ip": "198.51.100.4" }
]
```

The types that become alerts are `second_factor_failed`, `device_reported`, `email_change_reverted` and `clone_suspected`. A `second_factor_failed` alert is the classic sign that someone else knows the password.

Share them through your Inertia middleware to show a banner:

```php
// app/Http/Middleware/HandleInertiaRequests.php
public function share(Request $request): array
{
    return [
        ...parent::share($request),
        'keyringAlerts' => fn () => $request->session()->get('keyring.alerts', []),
    ];
}
```

## Security Emails

Keyring can email users about security events. These emails are off by default, since your app may want to send its own. Turn them all on in `KeyringServiceProvider`:

```php
Keyring::notify();
```

Or pick the ones you want:

```php
Keyring::notify(['new_device', 'second_factor_failed']);
```

You can also list types in the `notifications` config option. `Keyring::notify()` takes precedence over it.

Every email is a `Keyring\Notifications\SecurityNotice`, sent by mail and queued. Each one includes when it happened, the device and the IP address of the request that caused it.

### Email Types

| Type | Sent when |
|---|---|
| `new_device` | A sign in from a new device. Includes the ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link). |
| `password_changed` | The password was changed or reset. |
| `authenticator_added` | A sign-in method was added. |
| `authenticator_removed` | A sign-in method was removed. |
| `second_factor_failed` | Someone got the password right but failed the next factor. |
| `recovery_code_used` | A recovery code was used. Says how many are left. |
| `suspicious_activity` | A [risk action](risk.md#actions) with `notify()` ran. Lists the reasons. |
| `clone_suspected` | A passkey or security key looked cloned. |

To send your own instead, listen for the matching [events](sign-in-flow.md#events) and leave the type off.

### Customising the Copy

The wording lives in `lang/en/notifications.php`, keyed by type, with `subject`, `intro` and, for `new_device`, `action`. Publish it to change it:

```bash
php artisan vendor:publish --tag=keyring-lang
```

### Emails Keyring Always Sends

Some emails are part of a flow rather than a notice, so `Keyring::notify()` doesn't control them:

| Notification | Sent to |
|---|---|
| `VerificationCode` | The user, with an [email code](factors.md#email-codes). |
| `ResetPassword` | The user, with a reset link. |
| `ConfirmEmailChange` | The new address, during an email change. |
| `EmailChangeNotice` | The current address, during an email change. |
| `EmailAddressInUse` | An address someone tried to change their email to, when it already has an account. |

Laravel's own `VerifyEmail` notification is used for email verification, with a link Keyring builds from `APP_URL`.

All of these live in `Keyring\Notifications` and send immediately. Their text goes through Laravel's JSON translations, so you can translate the English strings in `lang/{locale}.json`.
