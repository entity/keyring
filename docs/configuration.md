# Configuration

- [Introduction](#introduction)
- [Durations](#durations)
- [Guard and Users](#guard-and-users)
- [Features](#features)
- [Registration](#registration)
- [Redirects](#redirects)
- [Routes](#routes)
- [WebAuthn](#webauthn)
- [Account Changes and Enrollment](#account-changes-and-enrollment)
- [Devices](#devices)
- [Sessions](#sessions)
- [Protected Attributes and Email Changes](#protected-attributes-and-email-changes)
- [Passwords](#passwords)
- [Risk](#risk)
- [Security Log](#security-log)
- [Pending Logins, Timebox and Rate Limits](#pending-logins-timebox-and-rate-limits)
- [Messages and Translations](#messages-and-translations)
- [The Keyring Facade](#the-keyring-facade)

## Introduction

Keyring is configured in two places:

- `config/keyring.php` holds values: your features, timeouts, limits, route options.
- `app/Providers/KeyringServiceProvider.php` holds behaviour: which factors exist, the policy, risk responses, swapped responses and pages. These calls go in the provider's `boot()` method.

`keyring:install` publishes a short config with the options most apps change: `guard`, `username`, `home`, `features`, `registration` and `enrollment_url`. Every other option on this page keeps its default until you copy it into that file. Keyring merges your file over its defaults key by key, so you can copy just the part you change, such as `'sessions' => ['absolute' => '7d']`. Lists, like `features`, are replaced whole. `php artisan vendor:publish --tag=keyring-config` gives you the full file instead.

## Durations

Options that take a duration accept a number of seconds or a string such as `"30s"`, `"15m"`, `"12h"` or `"7d"`. Anything else throws an `InvalidArgumentException`. The two short ones, `timebox` and `webauthn.timeout`, also accept milliseconds (`"250ms"`) and always need a unit.

## Guard and Users

```php
'guard' => 'web',

'username' => 'email',

'email' => 'email',
```

`guard` is the stateful guard users are signed into. Keyring stores pending logins, step-up state and enrollments in the session, so it needs a session-based guard.

`username` is the user attribute typed at login, and the field name the login form posts. Keyring lowercases what users type before looking them up, so store this attribute lowercased.

`email` is the attribute holding the user's address. It's the one the [email change flow](protected-changes.md#changing-the-email-address) changes and protects, the field the password reset forms post, and where an email code's hint comes from. Leave it as it is unless users sign in with something else, like a handle: then set `username` to that attribute and keep `email` pointing at the address.

## Features

```php
use Keyring\Features;

'features' => [
    Features::registration(),
    Features::resetPasswords(),
    Features::emailVerification(),
    Features::updatePasswords(),
    Features::securityLog(),
    // Features::manageAuthenticators(),
    // Features::devices(),
    // Features::emailChanges(),
],
```

Signing in and out, challenges and step-up are always on. Everything else is a feature: each one adds its routes, and anything else it needs, only once it's in the list. Without a config file, Keyring turns on registration, password resets, email verification, password changes and the security log, which is also what `keyring:install` picks unless you choose otherwise. The list is replaced whole by yours, so keep `Features::securityLog()` in it unless you'd rather have those events in [your app's log](security-log-and-emails.md#without-the-table). What each feature adds is in [Adding Features](quick-start.md#adding-features).

Check for a feature in your own code with `Features::enabled(Features::devices())`. `Features::all()` lists them all, which is handy in tests.

## Registration

```php
'registration' => [
    'reveal_taken' => false,
],
```

By default registering answers the same whether or not the address has an account: new users sign in once they've followed the link emailed to them, and an address that already has an account is emailed that someone tried to register with it. That needs `Features::emailVerification()` and a `MustVerifyEmail` user model, and the app doesn't boot with registration on and email verification off.

Set `reveal_taken` to `true` to answer "has already been taken" on the form and sign new users in straight away, which lets anyone check whether an address has an account. [Registration](sign-in-flow.md#registration) says exactly what each choice reveals.

## Redirects

```php
'home' => '/dashboard',
```

`home` is where users go after signing in or confirming, when there's no intended URL. It's also used after email verification (with `?verified=1` added) and after confirming an email change while signed in.

Signed-out users are sent to the route named `login`.

## Routes

```php
'routes' => true,

'prefix' => '',

'domain' => null,

'middleware' => ['web', AddSecurityHeaders::class],
```

Keyring registers its routes inside a group with this prefix, domain and middleware. `Keyring\Http\Middleware\AddSecurityHeaders` sends `Cache-Control: no-store, private`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and `Referrer-Policy: same-origin` on every Keyring response, and `Referrer-Policy: no-referrer` on the pages emailed links open. It leaves `X-Frame-Options` off a response that already says who may frame it, with a header of its own or a `frame-ancestors` directive, so a middleware listed after it here can allow framing. See [Links and Headers](security.md#links-and-headers). Take it out of the list if your app sets those headers itself, but keep the URLs of emailed links out of `Referer` headers some other way: they carry their token.

If you set `routes` to `false`, Keyring registers nothing, and you call `Keyring::routes()` where you want them, for example inside your own group:

```php
Route::prefix('account')->middleware('throttle:60,1')->group(fn () => Keyring::routes());
```

`Keyring::routes()` adds the `middleware` option, but not `prefix` or `domain`; your group decides those. To change the routes themselves, copy `vendor/entity/keyring/routes/keyring.php` into your app instead, and keep the route names: Keyring's controllers, emails and middleware link to routes by name (for example `login`, `keyring.confirm.challenge` and `keyring.devices.report`).

The browser package uses Keyring's default paths. If you change the prefix, tell it with [`configureRoutes({ prefix })`](frontend.md#changing-routes).

## WebAuthn

```php
'webauthn' => [
    'relying_party' => [
        'id' => env('KEYRING_WEBAUTHN_RP_ID'),
        'name' => env('KEYRING_WEBAUTHN_RP_NAME'),
    ],
    'origins' => [],
    'timeout' => '60s',
    'login_options_for' => '5m',
    'attestation_roots' => [],
    'algorithms' => ['ES256', 'EdDSA'],
    'minimum_rsa_bits' => 2048,
],
```

See [Passkeys & Security Keys](passkeys.md#relying-party-and-origins). `timeout` and `login_options_for` are [durations](#durations). `login_options_for` is how long the challenge of a [usernameless sign in](passkeys.md#signing-in-without-a-username) can be answered, and is never shorter than `timeout`.

`attestation_roots` lists the root certificates a new key's attestation has to chain to, as PEM text or paths to PEM files. It's only read for a factor set up with [`requireAttestation()`](passkeys.md#requiring-attestation), which refuses every key while the list is empty.

`algorithms` lists the signature algorithms keys may use, in order of preference: `ES256`, `EdDSA` and `RS256`. `RS256` is off by default, and `minimum_rsa_bits` is the shortest RSA key taken when it's on, never under 2048. See [Signature Algorithms](passkeys.md#signature-algorithms) for what turning it on gains and costs.

## Account Changes and Enrollment

```php
'changes_middleware' => ['keyring.fresh:15m'],
```

Extra middleware for adding, renaming and removing authenticators, revoking devices, changing the password and starting an email change. It's applied on top of `auth:{guard}`, which every signed-in Keyring route already has, so don't add `auth` here. By default these routes need a verification in the last 15 minutes. See [Step-Up](step-up.md#fresh-verification).

```php
'enrollment_url' => null,
```

Where the `keyring.enrolled` middleware sends users who still need a second factor. Null answers `403`. `keyring:install` sets it to `/settings/security` when you have it require a second factor for everyone. See [Requiring a Second Factor](policies.md#requiring-a-second-factor).

```php
'enrollment_except' => [],
```

More routes those users can still reach meanwhile, by route name, with `*` as a wildcard (`['billing.*', 'support']`). The enrollment page, Keyring's own routes, signing out, email verification and changing the password are always let through.

```php
'password_change_url' => null,
```

Where a user who has to choose a new password is sent from every other page until they have. Null answers `403`. See [Requiring a Password Change](protected-changes.md#requiring-a-password-change).

```php
'enrollments' => [
    'keep_for' => '15m',
],
```

How long a user has to finish adding a sign-in method once they've started. See [Adding an Authenticator](authenticators.md#adding-an-authenticator).

## Devices

```php
'devices' => [
    'cookie' => null,
    'cookie_lifetime' => '400d',
    'limit' => 50,
    'trust_for' => '30d',
    'report_link_for' => '7d',
    'keep_revoked_for' => '30d',
    'keep_unseen_for' => '365d',
    'locator' => NullLocator::class,
],
```

`cookie` is the name of the device cookie: `null` is `known_device`, with the `__Host-` prefix once your app is served over HTTPS (see [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies)), and a name you set is used exactly as it is. `cookie_lifetime` is how long the browser keeps it (400 days is the most browsers allow). `limit` is how many devices one account keeps: a sign in from a new browser beyond that forgets the device seen longest ago and signs it out. Set it to `null` for no limit. `trust_for` is how long "don't ask again on this device" lasts; set it to `null` to hide that option. `report_link_for` is how long a ["this wasn't me" link](devices-and-sessions.md#the-this-wasnt-me-link) works. [`keyring:prune`](devices-and-sessions.md#pruning) deletes a device `keep_revoked_for` after it was revoked, or `keep_unseen_for` after it was last seen. `locator` is the class that works out a request's location. See [Devices & Sessions](devices-and-sessions.md).

## Sessions

```php
'sessions' => [
    'driver' => env('KEYRING_SESSION_DRIVER', 'database'),
    'connection' => null,
    'table' => 'keyring_sessions',
    'store' => null,
    'max' => 100,
    'idle' => '2h',
    'remember_idle' => '14d',
    'absolute' => '30d',
    'levels' => [
        'aal2' => ['idle' => '1h', 'absolute' => '24h'],
        'aal3' => ['idle' => '15m', 'absolute' => '12h'],
    ],
    'end_on_lapse' => false,
    'middleware' => true,
    'remember_cookie' => null,
    'remember_grace' => '10s',
],
```

| Key | Means |
|---|---|
| `driver` | `database`, `cache`, or the name of a driver you've added. |
| `connection`, `table` | Used by the `database` driver. |
| `store` | The cache store used by the `cache` driver. `null` is your default store. |
| `max` | How many sessions one account can have at once. A sign in beyond that ends the one unused longest. `null` for no limit. See [How Many Sessions](devices-and-sessions.md#how-many-sessions). |
| `idle` | Inactivity allowed before a session ends. `null` leaves it to Laravel's session lifetime. |
| `remember_idle` | The same, for a browser that ticked "remember me": how long it may stay away and still be signed back in, with nothing proved. `null` lets it stay away for the whole `absolute` limit. See [Inactivity and "Remember Me"](devices-and-sessions.md#inactivity-and-remember-me). |
| `absolute` | The longest a session can last, however active it is. |
| `levels` | How long each assurance level keeps counting, as `idle` and `absolute`, keyed `aal1`, `aal2` or `aal3`. NIST's limits by default: AAL2 1h and 24h, AAL3 15m and 12h. |
| `end_on_lapse` | Whether a session ends when the level it signed in at runs out, where it would otherwise carry on at a lower one. See [Ending a Session With Its Level](devices-and-sessions.md#ending-a-session-with-its-level). |
| `middleware` | Whether Keyring adds its session middleware to the `web` group for you. |
| `remember_cookie` | The name of the cookie that ties ["remember me"](devices-and-sessions.md#remember-me) to the session it was ticked for. `null` is `remembered_session`, prefixed over HTTPS like the device cookie. See [Keyring's Cookies](devices-and-sessions.md#keyrings-cookies). |
| `remember_grace` | How long after that cookie is used the same browser's other requests, sent with it, are still let in on the same session. Each cookie works once; after this, [sending a used one again](devices-and-sessions.md#a-cookie-used-twice) ends the session. `0` leaves no room at all, so requests a browser sends together end it too. |

See [Devices & Sessions](devices-and-sessions.md#the-session-registry).

## Protected Attributes and Email Changes

```php
'protected' => [],

'email_changes' => [
    'confirmable_for' => '24h',
    'revertable_for' => '7d',
    'established_after' => '7d',
    'sign_out_others' => true,
    'keep_ended_for' => '30d',
],
```

`confirmable_for` is how long the emailed confirmation link works, and `revertable_for` how long the old address can undo the change afterwards. `established_after` is how long the account must have had a second factor before proving it lets a change skip the old address's confirmation, and how far back undoing a change removes sign-in methods. See [Confirming](protected-changes.md#confirming). `sign_out_others` ends the account's other sessions when an email change applies. `keep_ended_for` is how long a finished change is kept before `keyring:prune` deletes it.

`Features::updatePasswords()` adds `password` to the protected attributes, and `Features::emailChanges()` adds the [`email` attribute](#guard-and-users). List any others in `protected`. See [Protected Changes](protected-changes.md).

## Passwords

```php
'passwords' => [
    'min_with_mfa' => 8,
    'min_without_mfa' => 15,
    'max' => 128,
    'uncompromised' => null,
    'refuse_unchecked' => false,
    'context' => [],
    'broker' => null,
],
```

See [Password Rules](protected-changes.md#password-rules). `broker` is the password broker used for resets; `null` is your default broker.

`min_with_mfa` and `min_without_mfa` are counted in characters, and neither can be set below 8, the shortest password OWASP ASVS 6.2.1 and NIST SP 800-63B allow. With a lower one Keyring throws a `LogicException` as the app boots, and again wherever the option is read, instead of quietly using 8.

`max` is counted in characters, and how much of it you get depends on the hasher. Bcrypt, Laravel's default, only reads the first 72 bytes of a password, so with bcrypt Keyring refuses anything longer instead of ignoring the end of it. That makes the real limit 72 bytes, not 128 characters: 72 plain characters, but only 36 accented or Cyrillic ones, 24 Chinese, Japanese or Korean ones, or 18 emoji. OWASP ASVS 6.2.9 asks that passwords of at least 64 characters are allowed, which bcrypt can't promise. Hash with argon2id to take every password up to `max`:

```ini
HASH_DRIVER=argon2id
# While some users still have bcrypt hashes. They're rehashed as they sign in.
HASH_VERIFY=false
```

Keyring doesn't hash a password before bcrypt to get around the limit: the hashes would no longer be ones Laravel's own hasher can check. The [conformance suite](testing.md#the-conformance-suite) fails on bcrypt until you switch or say you're keeping it.

`context` is your list of words a password mustn't be made up of: the names of your organisation, products, systems, projects, departments and roles. It's the documented list OWASP ASVS 6.1.2 asks for, and Keyring always adds your app's name and what it knows about the user. See [Context-Specific Words](protected-changes.md#context-specific-words) for how they're compared.

`uncompromised` checks new passwords against Have I Been Pwned over the network. The default, `null`, runs it only when the app is in production, so local development and tests make no network calls. Set `true` or `false` to choose for every environment.

The check is Laravel's (`Password::uncompromised()`), and it fails open: when Have I Been Pwned can't be reached, times out or answers with an error, Laravel reports the exception and lets the password through. On those requests only the [bundled list](protected-changes.md#password-rules) of common passwords stands between a user and a breached password.

Set `refuse_unchecked` to `true` to refuse instead. Keyring then makes the request itself, the same way (only the first five characters of the password's SHA-1 leave your server), and a password it gets no answer about is refused with `keyring::keyring.password_unchecked`, which asks the user to try again in a moment. The cost is that nobody can register, or change or reset a password, while the service is unreachable from your servers. It only applies where `uncompromised` runs, and waits up to 10 seconds for an answer.

Laravel's check goes through whatever `Illuminate\Contracts\Validation\UncompromisedVerifier` is bound in the container, so you can bind one of your own, say for a copy of the breach data you host yourself. `refuse_unchecked` doesn't use it, since a verifier can only answer yes or no: leave the option off, and have your verifier answer `false` when it can't check.

## Risk

```php
'risk' => [
    'levels' => ['medium' => 30, 'high' => 60, 'critical' => 90],
    'recent_change' => '7d',
    'store' => null,
],
```

`levels` are the score thresholds. `recent_change` is how long after an email change the `RecentlyChangedRecovery` signal fires. `store` is the cache store for risk locks, `null` for your default store. Use a database or Redis store, not Octane's `octane` store: see [Octane's Cache Store](security.md#octanes-cache-store). See [Risk](risk.md).

## Security Log

```php
'security_log' => [
    'keep_for' => '180d',
    'channel' => env('KEYRING_LOG_CHANNEL'),
    'context_key' => 'trace_id',
    'refusals' => 20,
    'refusals_per' => '1h',
    'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected', 'remember_me_reused'],
],

'prune_at' => '03:00',
```

`keep_for` is how long entries are kept before [`keyring:prune`](devices-and-sessions.md#pruning) deletes them. `alerts` lists the entry types shown once as ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts) at the next sign in.

The table is `Features::securityLog()`, which is on by default. Without it the same events are written to the log `channel` (`null` is your default channel), and "was this you?" alerts and the `RepeatedFactorFailures` and `SuccessAfterFailures` risk signals don't work, since they read from the table. See [Without the Table](security-log-and-emails.md#without-the-table).

`context_key` is the key in Laravel's Context your app keeps a request's ID under, if it does, which every entry the request writes then carries. Without one Keyring makes an ID of its own for the request. `null` leaves it out. See [Request IDs](security-log-and-emails.md#request-ids).

`refusals` is how many entries of one type are written about one account, or from one IP address when no account is known, every `refusals_per`, for things that were refused and can be asked for again without end. `null` writes them all. See [Refusals That Repeat](security-log-and-emails.md#refusals-that-repeat).

`prune_at` is the time of day Keyring schedules `keyring:prune` for, which deletes everything that's past its time, not only log entries. `null` leaves scheduling it to you. See [Pruning](devices-and-sessions.md#pruning).

## Pending Logins, Timebox and Rate Limits

```php
'pending_logins' => [
    'keep_for' => '10m',
],

'timebox' => '250ms',

'limits' => [
    'per_account' => 5,
    'per_ip' => 20,
    'consecutive' => 100,
    'consecutive_elsewhere' => 80,
    'remember_names_for' => '30d',
    'longest_lock' => '24h',
    'longest_ip_lock' => '15m',
    'lock_after' => null,
    'codes' => 3,
    'codes_per' => '10m',
    'notices' => 5,
    'notices_per' => '1h',
],
```

`pending_logins.keep_for` is how long a half-finished login or confirmation stays valid, as a [duration](#durations). It's also the `expiresAt` shown on the challenge page.

`timebox` is the minimum time a refused verification takes, so timing doesn't reveal whether an account exists or whether a password refused for another reason was right. It covers every pipeline step, so a request refused by a rate limit or by validation waits too. Verifications that go through return straight away.

`limits` are the default attempts per minute for each factor, per account and per IP address, and `consecutive`, the failures in a row one of an account's authenticators allows before it's refused for that account (`null` for no cap, and 100 is the most NIST SP 800-63B allows). Those are counted in the `keyring_failure_counts` table, and nothing brings a refused authenticator back by itself: see [At the Cap](security.md#at-the-cap). `consecutive_elsewhere` is how many of them may come from browsers the account hasn't signed in from, which keeps the rest for the owner's own. It only applies with `Features::devices()` on, and `null` keeps nothing back. `remember_names_for` is how long the cache keeps the failures in a row counted under each typed username, which is what the sign-in form answers from.

The per-minute counts and their locks are kept in the cache store Laravel's rate limiter uses: `cache.limiter` in `config/cache.php`, or your default store. Point it at a database or Redis store. Octane's in-memory `octane` store fills up, isn't atomic across workers and is emptied by a restart: see [Octane's Cache Store](security.md#octanes-cache-store).

Each lockout lasts twice as long as the one before, up to `longest_lock`, or `longest_ip_lock` for a whole IP address. Set `lock_after` to refuse an account as it would be at the cap once it has been locked out of signing in that many times in a day, until its password is reset (see [Locking Until a Reset](security.md#locking-until-a-reset)). An account can be sent `codes` codes for one factor every `codes_per`, and `notices` security notices of one kind, or email change requests, every `notices_per`; an address is mailed that often by registration too. See [Rate Limiting](security.md#rate-limiting).

Keyring's form routes (registration, password reset, enrollment confirmation, email changes, verification emails and the emailed links) use a named rate limiter, `keyring`, which allows 6 requests a minute per user, or per IP address for guests. Define your own `keyring` limiter in a service provider's `boot()` method to change it:

```php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;

RateLimiter::for('keyring', fn (Request $request) => Limit::perMinute(10)->by($request->user()?->id ?: $request->ip()));
```

`GET /login/{factor}/options` uses its own limiter, `keyring-login-options`, which allows 60 requests a minute per IP address. Login pages fetch the options on every load for passkey autofill, and when the limit is hit autofill stops offering passkeys until the next minute. Define the same limiter to change it.

## Messages and Translations

Keyring's text lives in two translation files under the `keyring::` namespace:

| File | Holds |
|---|---|
| `lang/en/keyring.php` | Validation and error messages, such as `keyring::keyring.invalid`. |
| `lang/en/status.php` | The message for each status slug, such as `keyring::status.password-updated`. See [Status Responses](sign-in-flow.md#status-responses). |

Publish them to change the wording or add languages. The wording of emails is in [your notification classes](security-log-and-emails.md#security-emails) instead:

```bash
php artisan vendor:publish --tag=keyring-lang
```

## The Keyring Facade

`Keyring\Facades\Keyring` is the entry point for everything you set in code:

| Method | Does |
|---|---|
| `Keyring::factors([...])` | Sets the factors users can use. See [Factors](factors.md). |
| `Keyring::extend($key, $resolver)` | Adds one more factor from a closure. Its `key()` must match `$key`. |
| `Keyring::require($requirement)` | Sets the policy. See [Policies](policies.md). |
| `Keyring::pipeline($callback)` | Changes the verification steps. See [The Pipeline](sign-in-flow.md#the-verification-pipeline). |
| `Keyring::respondWith($contract, $implementation)` | Swaps a response. See [Responses](sign-in-flow.md#responses). |
| `Keyring::page($name, $component)` | Changes the component a page renders. See [Pages](sign-in-flow.md#pages). |
| `Keyring::risk()->signals([...])->respond(...)` | Configures risk signals and actions. `Keyring::risk()->push(...)` adds to the signals already on. See [Risk](risk.md). |
| `Keyring::notifications([...])` | Registers your notification class for each email Keyring sends. A security notice with none isn't sent, and unknown types throw an `InvalidArgumentException`. See [Security Emails](security-log-and-emails.md#security-emails). |
| `Keyring::createUsersUsing($action)` | Sets the registration action. See [Registration](sign-in-flow.md#registration). |
| `Keyring::resetUserPasswordsUsing($action)` | Sets the password reset action. See [Resetting the Password](protected-changes.md#resetting-the-password). |
| `Keyring::updateUserPasswordsUsing($action)` | Sets the password change action. See [Changing the Password](protected-changes.md#changing-the-password). |
| `Keyring::validateEmailChangesUsing($action)` | Sets the email change validation action. See [Requesting a Change](protected-changes.md#requesting-a-change). |
| `Keyring::routes()` | Registers Keyring's routes yourself, when `routes` is `false`. See [Routes](#routes). |
| `Keyring::useAuthenticatorModel($model)` | Uses your own subclass of `Keyring\Models\Authenticator`. |
| `Keyring::useDeviceModel($model)` | Uses your own subclass of `Keyring\Models\Device`. See [Your Own Device Model](devices-and-sessions.md#your-own-device-model). |
| `Keyring::usePendingChangeModel($model)` | Uses your own subclass of `Keyring\Models\PendingChange`. |
| `Keyring::useSecurityEventModel($model)` | Uses your own subclass of `Keyring\Models\SecurityEvent`. |
| `Keyring::attempt($request, $factor)` | Starts a sign in with a factor from a route of your own, through the same pipeline as the login form. See [Starting a Sign In Yourself](sign-in-flow.md#starting-a-sign-in-yourself). |
| `Keyring::requirePasswordChange($user, $reason = null)` | Holds a user until they choose a new password. `requiresPasswordChange($user)` asks whether they're held, and `cancelPasswordChange($user)` lets them go. See [Requiring a Password Change](protected-changes.md#requiring-a-password-change). |
| `Keyring::unlock($user)` | Lets a locked-out user try again without a password reset: lifts their risk lock and clears the limits, locks and failures in a row on the factors that can start a sign in. `Keyring::unlock($user, 'totp')` clears one factor's instead, such as a second factor refused at the cap. See [At the Cap](security.md#at-the-cap). |
| `Keyring::allowSignInWhen($callback)` | Decides who may be signed in at all, such as accounts that aren't banned. See [Who May Sign In](sign-in-flow.md#who-may-sign-in). |
| `Keyring::allowEnrollmentWhen($callback)` | Decides who may add a sign-in method, in place of the verified email rule. See [Who May Enroll](authenticators.md#who-may-enroll). |
| `Keyring::linkRootUsing($callback)` | Where emailed links start, in place of `APP_URL`. See [Emailed Links](security.md#emailed-links). |
| `Keyring::recordIpsUsing($callback)` | What Keyring stores as a request's IP address. See [What's Stored](security-log-and-emails.md#whats-stored). |
| `Keyring::describeDevicesUsing($callback)` | Names devices your own way, in place of "Firefox on Windows". See [Device Names](devices-and-sessions.md#device-names). |
| `Keyring::findUsersUsing($callback)` | Finds the user a typed username belongs to your own way, for a password sign in. See [Finding the User](sign-in-flow.md#finding-the-user). |
| `Keyring::normalizeUsernamesUsing($callback)` | Normalises usernames your own way. See [Finding the User](sign-in-flow.md#finding-the-user). |
| `Keyring::signInAfterRegistering($when)` | Whether registering signs the user in, where `registration.reveal_taken` lets it. See [Saying When an Address Is Taken](sign-in-flow.md#saying-when-an-address-is-taken). |
| `Keyring::findUser($request)` | The user a password sign in is for, for a primary factor of your own. |
| `Keyring::signsInAfterRegistering($user, $request)` | Whether registering signs this user in, for a registration flow of your own. |
| `Keyring::hidesRegisteredAddresses()` | Whether registration answers the same for a taken address, which it does unless `registration.reveal_taken` is on. |
| `Keyring::withoutProtection($callback, reason: ...)` | Changes protected attributes outside Keyring's flows. See [Protected Changes](protected-changes.md#bypassing-protection). |
| `Keyring::activity($user, $limit = 25)` | Recent security log entries. |
| `Keyring::for($user)` | The user's keyring, the same as `$user->keyring`. |
| `Keyring::user()` | The user signed in to Keyring's guard. Throws an `AuthenticationException` when there isn't one. |
| `Keyring::fake()` | Passes or fails factors in tests. See [Testing](testing.md). |

It also answers questions about your setup, for your own controllers, factors and steps:

| Method | Returns |
|---|---|
| `Keyring::registered()` | The registered factors, keyed by their key. |
| `Keyring::factor($key)` | One registered factor. `Keyring::hasFactor($key)` says whether there is one. |
| `Keyring::guard()` | Keyring's guard. `Keyring::provider()` is its user provider. |
| `Keyring::username()` | The username field, `email` by default. |
| `Keyring::normalizeUsername($username)` | A username as Keyring stores and looks it up. See [Finding the User](sign-in-flow.md#finding-the-user). |
| `Keyring::requirementFor($user, $attempt)` | What this user must prove to finish the attempt. See [Checking Requirements in Code](policies.md#checking-requirements-in-code). |
| `Keyring::statusMessage($status)` | The translated message for a status slug, or `null`. See [Flash Messages and Alerts](frontend.md#flash-messages-and-alerts). |
| `Keyring::render($name, $props)` | Renders one of Keyring's [pages](sign-in-flow.md#pages), as Inertia or Blade, for a route of your own. |
| `Keyring::hasNotification($type)` | Whether a notification is registered for a [type](security-log-and-emails.md#email-types). |
| `Keyring::protectedAttributes($user = null)` | The attributes that only change through Keyring's flows. Pass a user whose model keeps its password under another name to get that name. See [Protected Attributes](protected-changes.md#protected-attributes). |
| `Keyring::response($contract, ...$with)` | Builds one of Keyring's [responses](sign-in-flow.md#responses), yours when you swapped it, for a route of your own. |
| `Keyring::describeDevice($userAgent)` | A user agent as a name people recognise, or `null`. |
| `Keyring::linkRoot()` | Where emailed links start. |
| `Keyring::email()` | The attribute holding the user's address, `email` by default. |
| `Keyring::policy($user, $attempt)` | What the policy asks of this user, before considering what they've enrolled. |
| `Keyring::steps()` | The pipeline's steps, in order. `Keyring::dangerouslyChangedSteps()` lists the mandatory ones an app took out. |
| `Keyring::notification($type, $arguments)` | The app's notification for a type, or `null`. `Keyring::requiredNotification()` throws when there isn't one. |
| `Keyring::belongsToGuard($user)` | Whether Keyring's guard would load this user back, so they can be signed in. |
| `Keyring::recordedIp($request)` | The request's IP address as Keyring stores it. |
| `Keyring::allowsSignIn($user)` | Whether the app lets this user be signed in. See [Who May Sign In](sign-in-flow.md#who-may-sign-in). |
| `Keyring::allowsEnrollment($user)` | Whether the user may add a sign-in method. See [Who May Enroll](authenticators.md#who-may-enroll). |
| `Keyring::authenticatorModel()` | The authenticator model's class. `deviceModel()`, `pendingChangeModel()`, `securityEventModel()` and `failureCountModel()` do the same for theirs. |
