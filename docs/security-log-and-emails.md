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
    - [Slack, SMS and Other Channels](#slack-sms-and-other-channels)
    - [Using Your Own Notification Classes](#using-your-own-notification-classes)
- [Laravel's Auth Events](#laravels-auth-events)

## The Security Log

Keyring records sign ins, failures, lockouts, changes and automatic actions in the `keyring_events` table, as `Keyring\Models\SecurityEvent` rows. Each entry has a `type`, the user (when known), the `factor`, the `device_id`, the IP address, the user agent, `meta` and `created_at`.

The log never holds passwords, codes, tokens or session IDs.

Turn it on with `Features::securityLog()`. Its options:

```php
'security_log' => [
    'keep_for' => '180d',
    'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected'],
],
```

Without the feature, nothing is logged. "Was this you?" alerts and the `RepeatedFactorFailures` risk signal read from the log, so they need it too.

The log never gets in the way of a sign in. If a write fails, Keyring passes the error to `report()` and carries on, so the sign in, refusal or email goes ahead without it. If the log can't be read, there are no alerts and `RepeatedFactorFailures` finds nothing.

The one exception is `protection_bypassed`. If that entry can't be written, [`Keyring::withoutProtection()`](protected-changes.md#bypassing-protection) throws before it runs your callback, so a bypass never happens unlogged.

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
| `session_ended` | Keyring signed a session out on its own. | `reason`: `revoked`, `expired`, `idle`, `other_user` or `risk` |
| `email_change_requested`, `email_changed`, `email_change_reverted` | | |
| `password_changed` | | |
| `password_reset` | A reset completed and cleared the account's [sign-in lockouts](security.md#rate-limiting). | `sign_in_locks_cleared` |
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

`SecurityEvent` is mass prunable: entries older than `security_log.keep_for` (180 days) are deleted by `keyring:prune`, along with Keyring's other old records. Schedule it daily:

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('keyring:prune')->daily();
```

See [Pruning](devices-and-sessions.md#pruning).

## "Was This You?" Alerts

After a successful sign in, Keyring flashes `keyring.alerts` to the session: a list of log entries worth asking the user about, which they haven't seen yet. Each one is shown once.

```json
[
  { "type": "second_factor_failed", "factor": "totp", "at": "2026-11-08T09:12:00+00:00", "ip": "198.51.100.4" }
]
```

The types that become alerts are listed in `security_log.alerts`: by default `second_factor_failed`, `device_reported`, `email_change_reverted` and `clone_suspected`. Any [entry type](#entry-types) can go there. A `second_factor_failed` alert is the classic sign that someone else knows the password.

To read them yourself, call `Keyring\Activity\SecurityLog::pullAlerts($user)`. It returns the unseen alert entries, newest first, and marks them seen, so each comes back once.

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

Keyring can tell users about security events. It sends none until you list them in the `security_notices` config option. NIST SP 800-63B asks for `authenticator_added`, `authenticator_removed`, `password_changed` and `recovery_code_used`, and `keyring:install` offers to turn those four on:

```php
'security_notices' => ['password_changed', 'authenticator_added', 'authenticator_removed', 'recovery_code_used'],
```

Or turn them all on in `KeyringServiceProvider`:

```php
Keyring::sendSecurityNotices();
```

Or pick the ones you want:

```php
Keyring::sendSecurityNotices(['new_device', 'second_factor_failed']);
```

An unknown type throws an `InvalidArgumentException`, so a typo doesn't quietly turn an email off. You can also list types in the `security_notices` config option. `Keyring::sendSecurityNotices()` takes precedence over it.

Every notice is a `Keyring\Notifications\SecurityNotice`, sent by mail unless you [choose other channels](#slack-sms-and-other-channels), and queued once any open database transaction commits. Each one includes when it happened, the device and the IP address of the request that caused it.

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
| `email_changed` | An email change applied. Sent to both the old and the new address. |
| `email_change_reverted` | An email change was undone. Sent to the current address, and to the new one when the change had applied, without the device and IP that undid it. |

To send your own instead, listen for the matching [events](sign-in-flow.md#events) and leave the type off.

### Customising the Copy

All the wording for Keyring's emails lives in `lang/en/notifications.php`. Security notices are keyed by type, with `subject`, `intro` and, for `new_device`, `action`; `details` holds the labels for the when, device and IP address lines, and `footer` the closing line. The emails below that Keyring always sends have their own keys (`verification_code`, `confirm_email_change`, `email_change_notice` and `email_address_in_use`). Publish the file to change it:

```bash
php artisan vendor:publish --tag=keyring-lang
```

Anything a user or client can influence, such as an authenticator name, a device or a location, can't add links, images or other formatting to an email: it shows as plain text. So the `intro` of a security notice and its detail lines are always plain text, even if you add Markdown to them. `footer` has no such values and is still Markdown.

### Slack, SMS and Other Channels

Security notices use Laravel's notification channels, so they can go anywhere Laravel can send. Extend `SecurityNotice`, choose the channels in `via()` (per user if you like), and add the matching method. `content()` gives you the translated subject, intro, detail lines and action to build from:

```php
namespace App\Notifications;

use Illuminate\Notifications\Slack\SlackMessage;
use Keyring\Notifications\SecurityNotice as KeyringSecurityNotice;

class SecurityNotice extends KeyringSecurityNotice
{
    public function via(object $notifiable): array
    {
        return $notifiable->slack_webhook ? ['mail', 'slack'] : ['mail'];
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        $content = $this->content();

        // Slack reads <...> as a link, and an authenticator's name is whatever the user typed.
        return new SlackMessage()->text(htmlspecialchars($content['subject'].': '.$content['intro'], ENT_NOQUOTES));
    }
}
```

`content()` is plain text that can include what users and clients sent, on one line and capped in length, so escape it for the channel you send it to. To change the email, start from `parent::toMail($notifiable)`, which is already escaped. If you build your own `MailMessage` from `content()`, pass each line through `Keyring\Support\MailText::plain()`, because Laravel reads mail lines as Markdown.

Slack needs Laravel's `laravel/slack-notification-channel` package; see [Laravel's notification docs](https://laravel.com/docs/notifications#slack-notifications) for it and the other channels. Then register the class in your `KeyringServiceProvider`:

```php
Keyring::securityNoticesUsing(\App\Notifications\SecurityNotice::class);
```

`toArray()` is already there, so adding `database` or `broadcast` to `via()` works without more code. Keep the parent's constructor, since Keyring passes its arguments by name.

The copies of `email_changed` and `email_change_reverted` sent to an address that isn't the account's current one have no user to pass to your class, so they're always Keyring's own `SecurityNotice`, by mail.

### Emails Keyring Always Sends

Some emails are part of a flow rather than a notice, so `Keyring::sendSecurityNotices()` doesn't control them. They prove the person controls an inbox, so they're always email:

| Notification | Sent to |
|---|---|
| `VerificationCode` | The user, with an [email code](factors.md#email-codes). The last line differs when the code confirms a new email code sign-in method. |
| `ConfirmEmailChange` | The new address, during an email change. |
| `EmailChangeNotice` | The current address, during an email change. |
| `EmailAddressInUse` | An address someone tried to change their email to, when it already has an account. |

These live in `Keyring\Notifications`. `VerificationCode` sends straight away; the three email change emails are sent after the response, so timing doesn't reveal whether an address has an account.

Password resets and email verification use Laravel's own `ResetPassword` and `VerifyEmail` notifications, with links Keyring builds from `APP_URL`. Their copy comes from Laravel's translations, and you change them the usual Laravel way, for example by overriding `sendPasswordResetNotification()` on your user model. The reset email is also sent after the response.

### Using Your Own Notification Classes

Keyring resolves every notification above, and `SecurityNotice`, through the container, with named constructor arguments. To change one beyond its copy, extend it and bind your class in a service provider's `register()` method:

```php
use App\Notifications\BrandedVerificationCode;
use Keyring\Notifications\VerificationCode;

$this->app->bind(VerificationCode::class, BrandedVerificationCode::class);
```

Keep the parent's constructor parameters, since Keyring passes them by name.

## Laravel's Auth Events

Keyring dispatches Laravel's `Illuminate\Auth\Events\Failed`, `Lockout` and `PasswordReset` next to its own events, as Fortify does, so existing listeners keep working. See [Events](sign-in-flow.md#events).
