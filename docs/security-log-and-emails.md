# Security Log & Emails

- [The Security Log](#the-security-log)
    - [Entry Types](#entry-types)
    - [Showing Recent Activity](#showing-recent-activity)
    - [Pruning](#pruning)
    - [What's Stored](#whats-stored)
- ["Was This You?" Alerts](#was-this-you-alerts)
- [Security Emails](#security-emails)
    - [Email Types](#email-types)
    - [Emails a Flow Needs](#emails-a-flow-needs)
    - [Your Own Templates](#your-own-templates)
    - [Slack, SMS and Other Channels](#slack-sms-and-other-channels)
    - [Sending Something Else Entirely](#sending-something-else-entirely)
- [Laravel's Auth Events](#laravels-auth-events)

## The Security Log

Keyring records sign ins, failures, lockouts, changes and automatic actions in the `keyring_events` table, as `Keyring\Models\SecurityEvent` rows. Each entry has a `type`, the user (when known), the `factor`, the `device_id`, the IP address, the user agent, `meta` and `created_at`.

The log never holds passwords, codes, tokens or session IDs.

Turn it on with `Features::securityLog()`. Its options:

```php
'security_log' => [
    'keep_for' => '180d',
    'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected', 'remember_me_reused'],
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
| `locked_out` | A rate limit was hit, whether the answer said so or was that of a wrong password. Not linked to a user. | `retry_after` |
| `account_locked` | Failed attempts locked the account until a password reset (only with `limits.lock_after`). | |
| `signed_out` | The user signed out. | |
| `authenticator_added`, `authenticator_removed` | | `name` |
| `recovery_codes_generated` | | |
| `recovery_code_used` | | `remaining` |
| `new_device` | A sign in from a new device. | `device` |
| `device_revoked` | A device was signed out. | `device` |
| `device_reported` | A device was signed out from the "this wasn't me" link. | `device` |
| `sessions_revoked` | "Sign out everywhere else". | `count` |
| `session_ended` | Keyring signed a session out on its own. | `reason`: `revoked`, `expired`, `idle`, `other_user`, `reused`, `risk` or `not_allowed` |
| `remember_me_reused` | A ["remember me" cookie was used twice](devices-and-sessions.md#a-cookie-used-twice), and the session ended for both browsers. The entry's address and user agent are the request that brought the used one; `device_id` is the device the ended session was on. | `device` |
| `email_change_requested`, `email_changed`, `email_change_reverted` | | |
| `password_changed` | | |
| `password_reset` | A reset completed and cleared the account's [sign-in lockouts](security.md#rate-limiting). | `sign_in_locks_cleared` |
| `protection_bypassed` | `Keyring::withoutProtection()` was used. Linked to the signed-in user who did it. | `reason` |
| `clone_suspected` | A passkey or security key's counter went backwards. | `name` |
| `risk_denied`, `risk_reauthenticate`, `risk_locked`, `risk_step_up`, `risk_revoked_sessions`, `risk_notified` | A risk action did something. | `checkpoint`, `score`, `reasons` |

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

### What's Stored

Each entry keeps the request's IP address and user agent, as devices and sessions do, and security notices pass the address on. To keep less, say what to store. Rate limits always use the real address:

```php
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

// The network, not the machine. Or return null to keep none.
Keyring::recordIpsUsing(fn (Request $request) => IpUtils::anonymize((string) $request->ip()));
```

## "Was This You?" Alerts

After a successful sign in, Keyring flashes `keyring.alerts` to the session: a list of log entries worth asking the user about, which they haven't seen yet. Each one is shown once. With `Features::devices()` on, a browser the account hasn't signed in on before gets none, since it could be whoever caused them; they wait for one it has.

```json
[
  { "type": "second_factor_failed", "factor": "totp", "at": "2026-11-08T09:12:00+00:00", "ip": "198.51.100.4" }
]
```

The types that become alerts are listed in `security_log.alerts`: by default `second_factor_failed`, `device_reported`, `email_change_reverted`, `clone_suspected` and `remember_me_reused`. Any [entry type](#entry-types) can go there. A `second_factor_failed` alert is the classic sign that someone else knows the password.

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

Keyring writes no emails of its own. Every email it sends is a notification class in your app, published to `app/Notifications/Keyring` by `keyring:install` and registered in your `KeyringServiceProvider`:

```php
use App\Notifications\Keyring as Notifications;

Keyring::notifications([
    'verification_code' => Notifications\VerificationCode::class,
    'confirm_email_change' => Notifications\ConfirmEmailChange::class,
    'email_change_notice' => Notifications\EmailChangeNotice::class,
    'email_address_in_use' => Notifications\EmailAddressInUse::class,
    'password_changed' => Notifications\PasswordChanged::class,
    'authenticator_added' => Notifications\AuthenticatorAdded::class,
    'authenticator_removed' => Notifications\AuthenticatorRemoved::class,
    'recovery_code_used' => Notifications\RecoveryCodeUsed::class,
    // 'new_device' => Notifications\NewDevice::class,
    // 'second_factor_failed' => Notifications\SecondFactorFailed::class,
    // ...
]);
```

A security notice that isn't listed isn't sent, so that list is how you turn one on or off. NIST SP 800-63B asks for `authenticator_added`, `authenticator_removed`, `password_changed` and `recovery_code_used`, and `keyring:install` offers to turn those four on; the rest are there commented out. Calling `Keyring::notifications()` again adds to the list, `null` takes a type out, and an unknown type throws an `InvalidArgumentException`, so a typo doesn't quietly turn an email off.

An account is sent each kind of notice five times an hour at most (`limits.notices` every `limits.notices_per`), so nobody can make your app mail one person without end, by signing in from a new browser over and over, say. The [security log](#the-security-log) records every event either way. A `MustVerifyEmail` user gets none until their address is verified, because until then it's only what someone typed when registering.

The classes are ordinary Laravel notifications and they're yours: change the wording, the channels or the whole template, or register a different class altogether. Keyring builds each one through the container and passes what it has to say as named constructor arguments, so a class takes only the ones it wants.

### Email Types

The security notices, each sent to the user:

| Type | Sent when | Passes |
|---|---|---|
| `new_device` | A sign in from a new device. | `url`, the ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link) |
| `password_changed` | The password was changed or reset. | |
| `authenticator_added` | A sign-in method was added. | `name` |
| `authenticator_removed` | A sign-in method was removed. | `name` |
| `second_factor_failed` | Someone got the password right but failed the next factor. | |
| `recovery_code_used` | A recovery code was used. | `remaining`, how many are left |
| `suspicious_activity` | A [risk action](risk.md#actions) with `notify()` ran. | `reasons` |
| `clone_suspected` | A passkey or security key looked cloned. | `name` |
| `email_changed` | An email change applied. Sent to both the old and the new address. | |
| `email_change_reverted` | An email change was undone. Sent to the current address, and to the new one when the change had applied. | |

Every notice is also passed `when` (the time as text, in the app's timezone), `at` (the same moment as a date, to format for the user's own timezone or language), and the `device` and `ip` of the request that caused it. The copy of `email_change_reverted` sent to the new address leaves those two out, since that address may be whoever took the account.

`name`, `device` and `reasons` can hold what a user or browser sent: a key's name is whatever was typed. Keyring cuts each to one line of at most 500 characters, and it's still text to escape for wherever you show it. The published classes pass it through `Keyring\Support\MailText::plain()`, because Laravel reads mail lines as Markdown and a name could otherwise add a link to a genuine security email.

The published notices share an abstract `SecurityNotice` in the same folder, which holds the constructor, `via()` and `toMail()`. Each notice only says its subject and intro. They're queued once any open database transaction commits, so a change that's rolled back is never announced.

### Emails a Flow Needs

Four emails are part of a flow rather than a notice. The flow can't work without one, so it throws `Keyring\Exceptions\MissingNotification`, naming the type, when none is registered:

| Type | Sent to | Passes |
|---|---|---|
| `verification_code` | The user, with an [email code](factors.md#email-codes). | `code`, `minutes` until it expires, and `enrolling`, true when the code confirms a new email code sign-in method |
| `confirm_email_change` | The new address, during an email change. | `url` and `expiresAt` |
| `email_change_notice` | The current address, during an email change. | `email` (the new address, with most of its name hidden), `revertUrl`, and `confirmUrl` when this address must confirm too |
| `email_address_in_use` | An address someone tried to change their email to, when it already has an account. | |

`verification_code` sends straight away; the three email change emails are sent after the response, so timing doesn't reveal whether an address has an account. An email change is refused before anything is saved when one of its three is missing.

The email change emails, and the copies of `email_changed` and `email_change_reverted` that go to an address the account no longer has, are sent to a bare address: the `$notifiable` is an `AnonymousNotifiable` routed to mail, not your user. Keep `via()` and `toMail()` from reading user attributes in those classes.

Password resets and email verification use Laravel's own `ResetPassword` and `VerifyEmail` notifications, with links Keyring builds from `APP_URL`. You change them the usual Laravel way, for example by overriding `sendPasswordResetNotification()` on your user model. The reset email is also sent after the response.

### Your Own Templates

To use your own views, such as templates built with Maizzle, return them from `toMail()`. For one notice:

```php
namespace App\Notifications\Keyring;

use Illuminate\Notifications\Messages\MailMessage;

class PasswordChanged extends SecurityNotice
{
    // subject() and intro() as published.

    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject(__('Your password was changed'))
            ->view('emails.keyring.password-changed', [
                'when' => $this->when,
                'device' => $this->device,
                'ip' => $this->ip,
            ]);
    }
}
```

Blade's `{{ }}` escapes those values for HTML. [Emails With Maizzle](recipes.md#emails-with-maizzle) walks through it, and the [example app](https://github.com/entity/keyring-example#emails) builds every email this way: Maizzle templates compiled to Blade views, one shared by all ten notices, with a local page to preview them. To change every notice at once, edit `toMail()` in your `SecurityNotice`. A notification doesn't have to extend it either: any class whose constructor takes the arguments it wants will do, and `toMail()` may return a `Mailable`.

### Slack, SMS and Other Channels

Notifications can go anywhere Laravel can send. Choose the channels in `via()`, per user if you like, and add the matching method:

```php
namespace App\Notifications\Keyring;

use Illuminate\Notifications\Slack\SlackMessage;

class NewDevice extends SecurityNotice
{
    public function via(object $notifiable): array
    {
        return $notifiable->slack_webhook ? ['mail', 'slack'] : ['mail'];
    }

    public function toSlack(object $notifiable): SlackMessage
    {
        // Slack reads <...> as a link, and a user agent is whatever the browser sent.
        return (new SlackMessage)->text(htmlspecialchars($this->subject().': '.$this->device, ENT_NOQUOTES));
    }

    // subject(), intro() and action() as published.
}
```

Slack needs Laravel's `laravel/slack-notification-channel` package; see [Laravel's notification docs](https://laravel.com/docs/notifications#slack-notifications) for it and the other channels. For the `database` or `broadcast` channels, add a `toArray()`.

### Sending Something Else Entirely

Keyring dispatches an [event](events.md) for everything it sends a notice about, whether or not a notification is registered. To do something other than notify the user, leave the type out of `Keyring::notifications()` and listen for the event.

## Laravel's Auth Events

Keyring dispatches Laravel's `Illuminate\Auth\Events\Failed`, `Lockout` and `PasswordReset` next to its own events, as Fortify does, so existing listeners keep working. See [Events](sign-in-flow.md#events).
