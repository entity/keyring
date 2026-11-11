# Security Log & Emails

- [The Security Log](#the-security-log)
    - [Without the Table](#without-the-table)
    - [Entry Types](#entry-types)
    - [Severity](#severity)
    - [Request IDs](#request-ids)
    - [Refusals That Repeat](#refusals-that-repeat)
    - [Refused Links](#refused-links)
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

Keyring records sign ins, failures, lockouts, refusals, changes and automatic actions in the `keyring_events` table, as `Keyring\Models\SecurityEvent` rows. Each entry has a `type`, a `severity`, the user (when known), the `factor`, the `device_id`, the IP address, the user agent, a `request_id`, `meta` and `created_at`.

The log never holds passwords, codes, tokens, signatures, session IDs or anything else from the request body.

It's on as shipped: `Features::securityLog()` is in Keyring's default features, and in the list `keyring:install` writes unless you leave it out. Its options:

```php
'security_log' => [
    'keep_for' => '180d',
    'channel' => env('KEYRING_LOG_CHANNEL'),
    'context_key' => 'trace_id',
    'refusals' => 20,
    'refusals_per' => '1h',
    'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected', 'remember_me_reused'],
],
```

The log never gets in the way of a sign in. If a write fails, Keyring passes the error to `report()`, writes the entry to [the app's log](#without-the-table) instead and carries on, so the sign in, refusal or email goes ahead. If the log can't be read, there are no alerts and the `RepeatedFactorFailures` and `SuccessAfterFailures` risk signals find nothing.

The one exception is `protection_bypassed`. If that entry can't be written, [`Keyring::withoutProtection()`](protected-changes.md#bypassing-protection) throws before it runs your callback, so a bypass never happens unlogged.

### Without the Table

Take `Features::securityLog()` out of your features and nothing is written to `keyring_events`, but the events are still recorded: each one becomes a line in your app's log, so there is never nothing. The line is `Keyring: {type}` at the entry's [severity](#severity), with the user (`{morph class}:{id}`), `factor`, `device_id`, `ip`, `user_agent`, `request_id` and `meta` as its context. `channel` names the log channel, and `null` is your default one:

```php
// config/logging.php
'security' => ['driver' => 'daily', 'path' => storage_path('logs/security.log'), 'days' => 180],
```

```ini
KEYRING_LOG_CHANNEL=security
```

How long those lines are kept, and who can read them, is then up to that channel. ["Was this you?" alerts](#was-this-you-alerts), [`Keyring::activity()`](#showing-recent-activity) and the `RepeatedFactorFailures` and `SuccessAfterFailures` risk signals read from the table, so they need the feature on.

### Entry Types

| Type | Severity | When | `meta` |
|---|---|---|---|
| `signed_in` | info | A login completed. | `factors` |
| `confirmed` | info | A step-up completed. | `factors` |
| `factor_failed` | warning | A factor failed. | |
| `second_factor_failed` | warning | A factor failed during a login after a correct password. | |
| `locked_out` | warning | A rate limit started refusing an IP address for a factor, whether the answer said so or was that of a wrong password. [Logged once](#refusals-that-repeat), not for each request it refuses. Not linked to a user. | `retry_after` |
| `account_locked` | warning | Failed attempts got the password or a passkey refused until a password reset: the cap on failures in a row, or `limits.lock_after`. | |
| `signed_out` | info | The user signed out. | |
| `authenticator_added`, `authenticator_removed` | notice | | `name` |
| `recovery_codes_generated` | info | | |
| `recovery_code_used` | notice | | `remaining` |
| `new_device` | notice | A sign in from a new device. | `device` |
| `device_revoked` | info | A device was signed out. | `device` |
| `device_reported` | warning | A device was signed out from the "this wasn't me" link. | `device` |
| `sessions_revoked` | info | "Sign out everywhere else", one session ended from the sessions list, an administrator's `keyring:sign-out` for the user, or the first request refused for an account [the app keeps out](sign-in-flow.md#who-may-sign-in). | `count` |
| `session_ended` | info | Keyring signed a session out on its own. | `reason`: `revoked`, `expired`, `idle`, `other_user`, `reused`, `risk` or `not_allowed` |
| `remember_me_reused` | warning | A ["remember me" cookie was used twice](devices-and-sessions.md#a-cookie-used-twice), and the session ended for both browsers. The entry's address and user agent are the request that brought the used one; `device_id` is the device the ended session was on. | `device` |
| `email_change_requested` | info | | |
| `email_changed` | notice | | |
| `email_change_reverted` | warning | | |
| `password_changed` | notice | | |
| `password_reset` | notice | A reset completed and cleared the account's [sign-in lockouts](security.md#rate-limiting). | `sign_in_locks_cleared` |
| `protection_bypassed` | warning | `Keyring::withoutProtection()` was used. Linked to the signed-in user who did it. | `reason` |
| `clone_suspected` | critical | A passkey or security key's counter went backwards. | `name` |
| `risk_step_up`, `risk_reauthenticate`, `risk_notified` | notice | A risk action did something. | `checkpoint`, `score`, `reasons` |
| `risk_denied`, `risk_locked`, `risk_revoked_sessions` | warning | A risk action refused, locked or signed out. | `checkpoint`, `score`, `reasons` |
| `access_refused` | warning | A signed-in user asked for an authenticator, device or session that isn't theirs, or that doesn't exist (a 404 either way), or opened an email verification link made for another account (a 403). | `resource` (`authenticator`, `device`, `session` or `email_verification`), `id` (what was asked for, cut to 64 characters; for a session, its [handle](devices-and-sessions.md#listing-and-ending-sessions), never its registry ID) |
| `enrollment_refused` | warning | A sign-in method wasn't added. | `reason`: `invalid` (the factor turned the confirmation down: a wrong code, a key it won't take) or `not_allowed` (the account [may not add one yet](authenticators.md#who-may-enroll)) |
| `authenticator_removal_refused` | warning | A sign-in method was kept, because removing it would have left the user unable to sign in the way their policy requires. | `name` |
| `link_refused` | warning | An emailed link was refused. Linked to the user whose email change it was, when there is one. | `link` and `reason`, [below](#refused-links) |
| `verification_refused` | critical | A sign in or step-up was refused at the end because a [mandatory step](sign-in-flow.md#mandatory-steps) hadn't run for the request. | `skipped`, the steps |
| `refusals_limited` | warning | The entries above this one stopped being written for a while. See [Refusals That Repeat](#refusals-that-repeat). | `type`, the entry type that was left out |

A wrong password for an unknown account is logged as `factor_failed` with no user.

Form validation errors aren't logged: a missing field or a malformed address is an ordinary mistake, not an attempt on anything.

### Severity

Every entry has one of four severities, in its `severity` column as the `Keyring\Enums\Severity` enum. They're PSR-3 log levels, so an entry written to a [log channel](#without-the-table) goes out at its own level, and a channel's `level` filters them as it would anything else:

| Severity | Means |
|---|---|
| `info` | Someone did what they were allowed to. |
| `notice` | How the account signs in changed, or something worth a look if it wasn't expected. |
| `warning` | Something failed or was refused, or looks like someone else at work. |
| `critical` | A sign-in method or a safeguard can't be relied on: a cloned key, a pipeline that let a request past a mandatory step. |

`Severity::of($type)` gives the severity of a type. An entry type of your own is `info` unless you say otherwise:

```php
use Keyring\Activity\SecurityLog;
use Keyring\Enums\Severity;

app(SecurityLog::class)->record('exported_data', $user, severity: Severity::Notice);
```

To be told about the worst of them as they happen, query for them, or send the log to a channel that alerts:

```php
SecurityEvent::query()->where('severity', Severity::Critical)->where('created_at', '>', now()->subDay())->get();
```

### Request IDs

Every entry a request writes has the same `request_id`, so a failed second factor, the lockout it caused and the email it sent can be read together:

```php
SecurityEvent::query()->where('request_id', $event->request_id)->oldest('id')->get();
```

The ID comes from Laravel's [Context](https://laravel.com/docs/context). If your app already names its requests there, as Laravel's own docs do with `trace_id`, Keyring uses yours and never makes a second one:

```php
// A middleware of yours
Context::add('trace_id', (string) Str::uuid());
```

Set `security_log.context_key` to the key you use, hidden or not. Then your own log lines for the request carry the same ID as its entries, and so does a queued job the request dispatched. When nothing is there, Keyring makes a UUID for the request and keeps it in the hidden context, so it adds nothing to your log lines. An ID longer than 64 characters is cut to fit. Set the key to `null` to leave `request_id` empty.

### Refusals That Repeat

Whoever is refused can ask again as often as they like, and entries are kept for months, so a refusal isn't allowed to fill the table a request at a time:

- **A lock is logged when it starts.** `locked_out` is written once per factor and IP address, and not again until the wait that lock gave is over. Every request it refuses in between still dispatches the `Lockout` event (and Laravel's), so listeners of yours see each one.
- **Refusals are counted.** `locked_out`, `access_refused`, `enrollment_refused`, `authenticator_removal_refused`, `link_refused`, `verification_refused`, and `factor_failed` for a name nobody has, are each written at most `security_log.refusals` times every `refusals_per` (20 an hour). They're counted about the account the entry is linked to, or per IP address when it's linked to nobody.
- **The log says where it stopped.** The first entry left out is replaced by one `refusals_limited` entry naming its type, so a gap in the log is never silent.

A failed factor for a real account isn't counted this way: the account's own [rate limits](security.md#rate-limiting) already bound how often it can fail, and the `RepeatedFactorFailures` and `SuccessAfterFailures` risk signals count those entries. Set `refusals` to `null` to write every refusal. The counts live in the rate limiter's cache store, like the limits themselves.

### Refused Links

`link_refused` covers every emailed link Keyring checks:

| `link` | `reason` |
|---|---|
| `email_change_confirm`, `email_change_revert` | `token` when the token was wrong, `ended` when it was right but the change is over (expired, cancelled, already used or already undone), `unknown` when there's no such change: the link was made up, or its change was pruned long ago. Only pressing the page's button is logged, not opening the link. |
| `password_reset` | `token`: the token wasn't one sent to that address, or has expired. The entry holds neither the token nor the address. |
| A signed route's name, such as `keyring.devices.report.store` or `verification.verify` | `signature` when the signature didn't match, `expired` when it did and the link is out of date. |

Signed links are checked by the `keyring.signed` middleware, which is Laravel's `signed` with the log entry added: it refuses the same links with the same 403. Put it on a signed route of your own to have its refusals logged too:

```php
Route::get('/invitations/{invitation}', AcceptInvitation::class)->middleware('keyring.signed:relative')->name('invitations.accept');
```

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

`SecurityEvent` is mass prunable: entries older than `security_log.keep_for` (180 days) are deleted by `keyring:prune`, along with Keyring's other old records. Keyring [schedules it daily](devices-and-sessions.md#pruning) itself, so there's nothing to add.

When a user is force deleted, their entries are deleted with them rather than waiting out `keep_for`. A soft deleted user keeps theirs.

### What's Stored

Each entry keeps the request's IP address and user agent, as devices and sessions do, and security notices pass the address on. To keep less, say what to store. Rate limits always use the real address:

```php
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\IpUtils;

// The network, not the machine. Or return null to keep none.
Keyring::recordIpsUsing(fn (Request $request) => IpUtils::anonymize((string) $request->ip()));
```

Everything Keyring keeps, how it's protected and for how long is listed in [What Keyring Keeps](security.md#what-keyring-keeps).

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
    'already_registered' => Notifications\AlreadyRegistered::class,
    'password_changed' => Notifications\PasswordChanged::class,
    'authenticator_added' => Notifications\AuthenticatorAdded::class,
    'authenticator_removed' => Notifications\AuthenticatorRemoved::class,
    'recovery_code_used' => Notifications\RecoveryCodeUsed::class,
    'recovery_codes_generated' => Notifications\RecoveryCodesGenerated::class,
    'email_changed' => Notifications\EmailChanged::class,
    'account_locked' => Notifications\AccountLocked::class,
    // 'new_device' => Notifications\NewDevice::class,
    // 'second_factor_failed' => Notifications\SecondFactorFailed::class,
    // ...
]);
```

A security notice that isn't listed isn't sent, so that list is how you turn one on or off. NIST SP 800-63B asks for `authenticator_added`, `authenticator_removed`, `password_changed` and `recovery_code_used`, and `keyring:install` registers those four with `recovery_codes_generated`, `email_changed` and `account_locked` unless you answer no (or pass `--no-emails`), whichever sign-in methods you picked. Every notice's class is published either way, so turning another on or off is one line in that list.

OWASP ASVS 5.0.0 asks for more. Requirement 6.3.7 is a notice after a change to how someone signs in: `password_changed`, `authenticator_added`, `authenticator_removed`, `recovery_codes_generated` and `email_changed`, which the installer has registered. Requirement 6.3.5 is a notice of a suspicious attempt: `new_device`, `second_factor_failed`, `account_locked`, and `suspicious_activity` with the [risk signals](risk.md#built-in-signals) you pick. Register the ones that are still commented out to meet it. [OWASP ASVS](owasp-asvs.md) has the whole list for each level.

Calling `Keyring::notifications()` again adds to the list, `null` takes a type out, and an unknown type throws an `InvalidArgumentException`, so a typo doesn't quietly turn an email off.

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
| `recovery_codes_generated` | A new set of recovery codes was made, and any earlier set stopped working. Sent for the set that comes with a user's first extra sign-in method too. | |
| `account_locked` | Failed attempts got the password or a passkey refused until the password is reset: it reached [the cap on failures in a row](security.md#at-the-cap), or [`limits.lock_after`](security.md#locking-until-a-reset) held it. Browsers the account has signed in from may still get in. | `url`, the password reset form (the `password.request` route), when the app has one. `device` and `ip` are those of the attempt that locked it. |
| `suspicious_activity` | A [risk action](risk.md#actions) with `notify()` ran. | `reasons` |
| `clone_suspected` | A passkey or security key looked cloned. | `name` |
| `email_changed` | An email change applied. Sent to both the old and the new address. | |
| `email_change_reverted` | An email change was undone. Sent to the current address, and to the new one when the change had applied. | |

Every notice is also passed `when` (the time as text, in the app's timezone), `at` (the same moment as a date, to format for the user's own timezone or language), and the `device` and `ip` of the request that caused it. The copy of `email_change_reverted` sent to the new address leaves those two out, since that address may be whoever took the account.

Renaming a sign-in method, or choosing another as the default, sends nothing: neither changes what can sign in to the account.

`name`, `device` and `reasons` can hold what a user or browser sent: a key's name is whatever was typed. Keyring cuts each to one line of at most 500 characters, and it's still text to escape for wherever you show it. The published classes pass it through `Keyring\Support\MailText::plain()`, because Laravel reads mail lines as Markdown and a name could otherwise add a link to a genuine security email.

The published notices share an abstract `SecurityNotice` in the same folder, which holds the constructor, `via()` and `toMail()`. Each notice only says its subject and intro. They're queued once any open database transaction commits, so a change that's rolled back is never announced.

### Emails a Flow Needs

Five emails are part of a flow rather than a notice. The flow can't work without one, so it throws `Keyring\Exceptions\MissingNotification`, naming the type, when none is registered:

| Type | Sent to | Passes |
|---|---|---|
| `verification_code` | The user, with an [email code](factors.md#email-codes). | `code`, `minutes` until it expires, and `enrolling`, true when the code confirms a new email code sign-in method |
| `confirm_email_change` | The new address, during an email change. | `url` and `expiresAt` |
| `email_change_notice` | The current address, during an email change. | `email` (the new address, with most of its name hidden), `revertUrl`, and `confirmUrl` when this address must confirm too |
| `email_address_in_use` | An address someone tried to change their email to, when it already has an account. | |
| `already_registered` | An address someone tried to [register](sign-in-flow.md#without-revealing-who-has-an-account) with, when it already has an account. | `loginUrl`, and `resetUrl` when password resets are on |

`verification_code` sends straight away; the three email change emails and `already_registered` are sent after the response, so timing doesn't reveal whether an address has an account. An email change is refused before anything is saved when one of its three is missing, and so is a registration without `already_registered`, unless `registration.reveal_taken` is on.

The email change emails, `already_registered`, and the copies of `email_changed` and `email_change_reverted` that go to an address the account no longer has, are sent to a bare address: the `$notifiable` is an `AnonymousNotifiable` routed to mail, not your user. Keep `via()` and `toMail()` from reading user attributes in those classes.

Password resets and email verification use Laravel's own `ResetPassword` and `VerifyEmail` notifications, with links Keyring builds from `APP_URL`. You change them the usual Laravel way, for example by overriding `sendPasswordResetNotification()` on your user model. The reset email is also sent after the response, and so is a new user's verification email, unless `registration.reveal_taken` is on.

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

Blade's `{{ }}` escapes those values for HTML. [Emails With Maizzle](recipes.md#emails-with-maizzle) walks through it, and the [example app](https://github.com/entity/keyring-example#emails) builds every email this way: Maizzle templates compiled to Blade views, one shared by every notice, with a local page to preview them. To change every notice at once, edit `toMail()` in your `SecurityNotice`. A notification doesn't have to extend it either: any class whose constructor takes the arguments it wants will do, and `toMail()` may return a `Mailable`.

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
