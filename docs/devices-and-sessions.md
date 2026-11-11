# Devices & Sessions

- [Introduction](#introduction)
- [Routes](#routes)
- [Devices](#devices)
    - [Trusted Devices](#trusted-devices)
    - [New Device Sign Ins](#new-device-sign-ins)
    - [The "This Wasn't Me" Link](#the-this-wasnt-me-link)
    - [Locations](#locations)
    - [Device Names](#device-names)
    - [Your Own Device Model](#your-own-device-model)
- [Listing and Revoking Devices](#listing-and-revoking-devices)
- [Listing and Ending Sessions](#listing-and-ending-sessions)
- [The Session Registry](#the-session-registry)
    - [Drivers](#drivers)
    - [Writing a Driver](#writing-a-driver)
    - [How Many Sessions](#how-many-sessions)
    - [The Session Middleware](#the-session-middleware)
    - ["Remember Me"](#remember-me)
    - [A Cookie Used Twice](#a-cookie-used-twice)
- [Keyring's Cookies](#keyrings-cookies)
- [For Administrators](#for-administrators)
- [Timeouts](#timeouts)
    - [Inactivity and "Remember Me"](#inactivity-and-remember-me)
- [Pruning](#pruning)
- [Events](#events)

## Introduction

Keyring tracks two things:

- **Devices**: browsers the user has signed in from, recognised by a cookie. A device is an input to your policy and to risk signals. It's never a factor. Devices are a feature, `Features::devices()`.
- **Sessions**: each signed-in session, kept in Keyring's own registry so they can be listed and revoked whatever session driver Laravel uses (database, file, cookie or cache). Sessions are always on: they're how Keyring signs other sessions out after a password change, ends idle ones, and lapses assurance levels.

```php
'features' => [
    Features::devices(),
],
```

Because sessions are always kept, the routes that [list and end them](#listing-and-ending-sessions) are always registered. No feature turns them on or off.

With devices on, Keyring sets its cookie on sign in, offers "don't ask again on this device", lists where the user is signed in, and adds "this wasn't me" links. Without it, no cookie is set and no device is recorded. The `NewDevice`, `NewCountry`, `ImpossibleTravel` and `InactiveAccount` [risk signals](risk.md) need devices. So does a separate limit for the owner's own known device, which stops someone else's failed guesses from locking them out there.

## Routes

| Method | URI | Name | Middleware | Does |
|---|---|---|---|---|
| `GET` | `/user/sessions` | `keyring.sessions.index` | `auth:{guard}` | Lists the user's sessions as JSON. |
| `DELETE` | `/user/sessions/{id}` | `keyring.sessions.destroy` | `auth:{guard}`, `changes_middleware` | Ends one session. |
| `DELETE` | `/user/sessions` | `keyring.sessions.destroy-others` | `auth:{guard}`, `changes_middleware` | Signs out every other session. |
| `GET` | `/user/devices` | `keyring.devices.index` | `auth:{guard}` | Lists the user's devices as JSON. |
| `DELETE` | `/user/devices/{id}` | `keyring.devices.destroy` | `auth:{guard}`, `changes_middleware` | Signs one device out. |
| `DELETE` | `/user/devices` | `keyring.devices.destroy-others` | `auth:{guard}`, `changes_middleware` | Signs out every other session. |
| `GET` | `/devices/{id}/report` | `keyring.devices.report` | signed, `keyring` limiter | The "this wasn't me" link: a page with a button. |
| `POST` | `/devices/{id}/report` | `keyring.devices.report.store` | signature in the body, `keyring` limiter | Signs the device out. |

The three session routes are always registered. The device routes need `Features::devices()`. Looking needs only a signed-in user. Ending anything also needs `changes_middleware`, a [fresh verification](step-up.md#fresh-verification) by default.

## Devices

With `Features::devices()` on, on every sign in Keyring looks for its device cookie. If it's missing or unknown, Keyring creates a device with a new random token and sets the cookie. The cookie is httpOnly, `SameSite=Lax` and lasts 400 days. Only a SHA-256 hash of the token is stored. See [Keyring's Cookies](#keyrings-cookies) for its name and when it's `Secure`.

An account keeps its 50 most recently seen devices (`devices.limit`). A sign in from another new browser forgets the one seen longest ago and signs it out, so it's a new device if it comes back. Without a limit, one account could fill the table and its own devices page just by signing in from browsers that send no cookie.

Each device records a readable name built from the user agent (the browser and the operating system, as in ":browser on :platform"), the last IP address and location, and when it was first and last seen. The user agent is never a factor. It's only a weak risk signal: `SessionFingerprintChanged` notices when a session's browser or platform changes.

A browser shared by several accounts has one cookie and a device for each account that signed in on it. An account's device never takes a value the browser sent: Keyring can't tell a cookie two accounts share from one that was placed in the browser holding a value someone else's device has, and taking it would get that someone's own browser recognised as this account's. So an account signing in on a browser for the first time gives it a new cookie, and the accounts already on that browser move to the new one with it. Every login that reaches AAL2 gives the browser a new cookie too, so the previous one stops working.

### Trusted Devices

When `devices.trust_for` isn't `null`, the challenge page offers "don't ask again on this device" (`canTrustDevice`). Posting `trust: true` during the login marks the device trusted for that long (30 days by default), counted from the moment it's granted. It only counts when that login reached AAL2, with a password and an authenticator app's code, say, and, with `Features::emailVerification()` on, the email address is verified. An [emailed code](factors.md#email-codes) isn't a factor, so a login that used one beside the password isn't offered trust (`canTrustDevice` is false) and can't earn it. Sending it with the password, or after a login that only used the password, is ignored. Granting trust gives the browser a new cookie, so trust never rests on a cookie that was planted or copied before the login. Other accounts on the same browser move to the new cookie too.

Trust on its own changes nothing. It's for your [policy](policies.md#deciding-per-user-and-attempt) to use:

```php
Keyring::require(fn (User $user, Attempt $attempt) => $attempt->device()?->isTrusted()
    ? Requirement::aal1()
    : Requirement::aal2()->ifEnrolled());
```

Revoking a device stops trusting it. Signing out everywhere else stops trusting every other device. Every device stops being trusted when the password changes or is reset, when an authenticator is removed or a one-per-user factor is replaced (new recovery codes don't count), when an email change is applied or reverted, when a signed-in request places a [risk lock](risk.md#responding-to-risk), and after a critical risk on a signed-in session. Risk at login leaves the owner's sessions and trusted devices alone, whether it refuses the attempt or locks the account.

### New Device Sign Ins

A sign in from a new device dispatches `Keyring\Events\NewDeviceSignedIn`. The `new_device` [security email](security-log-and-emails.md#security-emails) tells the user, and `keyring:install` registers it when devices are on. Or send your own:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\NewDeviceSignedIn;

Event::listen(function (NewDeviceSignedIn $event) {
    $event->user->notify(new NewSignIn($event->device->description(), $event->revokeUrl()));
});
```

`$device->description()` adds the place when it's known, as in ":browser on :platform near :city".

### The "This Wasn't Me" Link

`$event->revokeUrl()` (or `$device->revokeUrl($days)`) returns a signed link to `GET /devices/{id}/report`, valid for 7 days by default (`devices.report_link_for`). Opening it shows the `device-report` page. Its props are `device` (a description such as "Chrome on macOS"), `url`, `expires` and `signature`, and its button posts `expires` and `signature` in the body to `url`, which is the link's path without its query string. That revokes the device without the user signing in: its sessions end, it stops being trusted, and every "remember me" cookie for the user stops working. The user lands on the login page with a message recommending a password change. The event is logged as `device_reported`, which shows as a ["was this you?" alert](security-log-and-emails.md#was-this-you-alerts) at their next sign in.

The link is built from `APP_URL`, and its signature covers only the path and query, so a forged `Host` header can't point it at another site. Like the email change links, opening it changes nothing, so mail scanners that open links can't sign anyone out.

The link has to carry its signature in the URL. The request that acts posts it instead, so it isn't written to access logs and proxies a second time. Keyring checks the posted fields as it checked the link: the same signature, over the same path, with the same expiry. A signature left in the `POST`'s URL is refused with a `403`.

```html
<form method="POST" action="{{ $url }}">
    @csrf
    <input type="hidden" name="expires" value="{{ $expires }}">
    <input type="hidden" name="signature" value="{{ $signature }}">
    <button>Sign {{ $device }} out</button>
</form>
```

### Locations

Keyring asks a locator class for each request's rough location. The default `Keyring\Devices\NullLocator` knows nothing, so locations are empty and the location [risk signals](risk.md) stay quiet.

To turn locations on, set `devices.locator` to a class implementing `Keyring\Contracts\LocatesIps`. [Recipes](recipes.md#locations-with-stevebaumanlocation) has one for `stevebauman/location`:

```php
use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;

class IpLocator implements LocatesIps
{
    public function locate(Request $request): ?array
    {
        $record = app(IpDatabase::class)->lookup($request->ip());

        return $record === null ? null : [
            'country' => $record->countryCode,
            'city' => $record->city,
            'latitude' => $record->latitude,
            'longitude' => $record->longitude,
        ];
    }
}
```

The array may contain `country`, `region`, `city`, `latitude` and `longitude`. Impossible travel needs the coordinates.

Keyring asks the locator at most once per request, however many signals and steps need the location. Read it the same way in your own code with `Keyring\Devices\Location::of($request)`.

If the locator throws (say its database file is missing), the location is unknown for that request and the exception goes to `report()`. Sign in carries on and the location risk signals stay quiet.

`Keyring\Devices\HeaderLocator` reads the location headers a proxy or CDN adds. By default it reads Cloudflare's: `CF-IPCountry`, `CF-Region`, `CF-IPCity`, `CF-IPLatitude` and `CF-IPLongitude`. For another proxy, set `devices.locator` to `HeaderLocator::class` and bind it with your own map of location fields to header names:

```php
use Keyring\Devices\HeaderLocator;

$this->app->bind(HeaderLocator::class, fn () => new HeaderLocator([
    'country' => 'X-Country-Code',
    'city' => 'X-City',
]));
```

Only use it when requests can't reach your app without passing through that proxy, since anyone can send those headers.

### Device Names

Keyring's own user agent parsing only knows the common browsers and platforms. To use a real parser, pass a closure that receives the user agent string and returns a name, or `null`, in a service provider's `boot()` method:

```php
use Keyring\Facades\Keyring;

Keyring::describeDevicesUsing(fn (string $userAgent) => app(UserAgentParser::class)->parse($userAgent)->summary());
```

`UserAgent::from($request)` returns the request's user agent trimmed to 500 characters, as Keyring stores it.

### Your Own Device Model

To add relationships or methods to devices, extend `Keyring\Models\Device` and tell Keyring about it:

```php
use App\Models\Device;

Keyring::useDeviceModel(Device::class);
```

`$user->devices()`, the risk signals, `keyring:prune` and the device routes all use it. The model has two query scopes, `ownedBy($user)` and `active()` (not revoked):

```php
Keyring::deviceModel()::query()->ownedBy($user)->active()->get();
```

## Listing and Revoking Devices

With `Features::devices()` on, `GET /user/devices` returns the user's devices that haven't been revoked, most recently seen first. A device is a browser, with however many sessions it has (`sessions`); for the sessions themselves, see [Listing and Ending Sessions](#listing-and-ending-sessions).

```json
{
  "devices": [
    {
      "id": "01JC6...",
      "name": "<browser> on <platform>",
      "description": "<browser> on <platform> near Leeds",
      "ip": "203.0.113.7",
      "location": { "country": "GB", "city": "Leeds" },
      "lastActiveAt": "2026-11-08T13:55:00+00:00",
      "trusted": false,
      "current": true,
      "sessions": 1
    }
  ]
}
```

`DELETE /user/devices/{id}` revokes one device: its sessions end, it stops being trusted, and the user's "remember me" token is changed. The response is a [status response](sign-in-flow.md#status-responses) with `device-revoked`. Revoking the current device also signs this session out, and the response redirects to the login page (JSON clients get it as `redirect`).

`DELETE /user/devices` and [`DELETE /user/sessions`](#listing-and-ending-sessions) are the same thing under two names. The second is registered whether or not `Features::devices()` is on, so "sign out everywhere else" is always there to offer. Either one signs out every session except the current one, changes the "remember me" token, stops trusting every other device, cancels any pending email change, and gives the current session a new ID, so someone who copied its cookie is signed out too. It responds with `sessions-revoked`. Do the same from your own code with `Keyring\Sessions\Sessions::signOutOthers()`, which returns how many sessions it revoked and dispatches `SessionsRevoked`. It's `signOutEverywhere()` with the current session left out, then `rotate()`, which gives the current session its new ID:

```php
use Keyring\Sessions\Sessions;

app(Sessions::class)->signOutOthers($request, $user);

// Or step by step.
app(Sessions::class)->signOutEverywhere($user, except: app(Sessions::class)->current($request)?->id);

app(Sessions::class)->rotate($request);
```

A user can also ask for this [along with adding or removing a sign-in method](authenticators.md#signing-out-other-sessions), and a [password change](protected-changes.md#changing-the-password) does it unless told not to.

`rotate()` regenerates the session, which destroys the old one on the server. Laravel's `cookie` session driver has nothing on the server to destroy, so there `rotate()` also moves the session to a new registry record and revokes the old one. Keyring calls it after every step-up too, and a browser that signs in while it's already signed in has the session it was on revoked, so on any driver a copy of the session from before is signed out on its next request.

Laravel keeps one "remember me" token per user, so changing it signs out every remembered browser at once, including the current one the next time its session ends. Signing out on purpose changes it, as Laravel does. A session that ends on its own (an idle or absolute timeout, a risk response, or a revoked record) leaves the token alone, so other remembered browsers stay signed in. That browser's cookies stop working because its record has ended: see ["Remember Me"](#remember-me).

## Listing and Ending Sessions

`GET /user/sessions` returns every session the user could still carry on, most recently active first. It reads the registry, so it's the whole list: a session with no device, such as one your own `Auth::login()` started in a browser Keyring hadn't seen, and each of two sessions on the same device.

```json
{
  "sessions": [
    {
      "id": "9f2c41d0...",
      "name": "<browser> on <platform>",
      "ip": "203.0.113.7",
      "device": "01JC6...",
      "remembered": false,
      "signedInAt": "2026-11-08T09:12:00+00:00",
      "lastActiveAt": "2026-11-08T13:55:00+00:00",
      "expiresAt": "2026-12-08T09:12:00+00:00",
      "current": true
    }
  ]
}
```

`device` is the ID of the session's [device](#listing-and-revoking-devices), or `null` when it has none or devices are off, so a page can show sessions under their devices. `lastActiveAt` is kept to the minute. A session that has been revoked, has expired, has [idled out](#timeouts) or has moved to another record isn't listed.

`id` is a handle, not the session's registry ID. The registry ID is what the ["remember me" cookie](#remember-me) carries, so it never leaves the server any other way: a page that could read it could hand someone the session. The handle is an HMAC-SHA256 of that ID under your `APP_KEY`. It can't be turned back into the ID, it's the wrong length to be taken for one, and the only thing that accepts it is the route below, which looks for it among the signed-in user's own sessions. A session that moves to a new record gets a new handle, so fetch the list again before acting on an old one.

`DELETE /user/sessions/{id}` ends the session with that handle. Its record is revoked, so that browser is signed out on its next request and its "remember me" cookie brings nothing back. The response is a [status response](sign-in-flow.md#status-responses) with `session-revoked`, and `SessionsRevoked` is dispatched with a count of one. The user's "remember me" token is left alone, so their other remembered browsers stay signed in. A handle that isn't one of the user's own sessions, someone else's included, gets a `404` and is logged as `access_refused`. Anything that isn't shaped like a handle, a registry ID included, doesn't match the route at all.

Ending the current session is signing out: Keyring does everything `POST /logout` does, including changing the "remember me" token and dispatching `LoggedOut`, and answers with the same [`LogoutResponse`](sign-in-flow.md#signing-out). A JSON client gets a `204`, so send the user to your login page when `current` was `true`.

`DELETE /user/sessions` signs out every session but this one. See [below](#listing-and-revoking-devices) for everything it ends.

From your own code:

```php
use Keyring\Sessions\Sessions;

$sessions = app(Sessions::class);

$sessions->list($request, $user);            // what the route returns
$sessions->active($user);                    // the same sessions as RegisteredSession objects

$session = $sessions->find($user, $handle);  // null unless it's one of the user's own
$sessions->revoke($user, $session);
```

## The Session Registry

Every signed-in session gets a record in Keyring's registry, with its own random ID, the user, the device, the assurance level, the IP address, the user agent, whether "remember me" was ticked, and its timestamps. Laravel's session ID is never stored. The registry ID lives inside the session.

A session can move to a new record: when ["remember me"](#remember-me) carries it on, when a [risk response](risk.md#actions) asks it to verify again, and with `rotate()` on the `cookie` session driver, which includes every step-up. The old record then names the new one (`replacedBy`, `replacedAt`) and stops being a session: it isn't listed, counted or revoked with the user's sessions.

Because Keyring checks the registry on every request, revoking a session takes effect on its next request, whichever session driver you use.

### Drivers

```php
'sessions' => [
    'driver' => env('KEYRING_SESSION_DRIVER', 'database'),
    'connection' => null,
    'table' => 'keyring_sessions',
    'store' => null,
    // ...
],
```

- **`database`** (the default) uses the `keyring_sessions` table on `connection`.
- **`cache`** uses the cache store named in `store` and needs no table. Use a persistent store: if the cache is cleared, every session's record is gone, and everyone is signed out on their next request. Revocations are kept under their own keys, so a request saving a stale copy of a session can't undo one.

### Writing a Driver

Implement `Keyring\Contracts\SessionRegistry` and register it with the registry manager in a service provider's `register()` method:

```php
use Keyring\Sessions\SessionRegistryManager;

$this->app->afterResolving(SessionRegistryManager::class, function (SessionRegistryManager $manager) {
    $manager->extend('custom', fn ($app) => new MySessionRegistry($app->make('db')->connection('sessions')));
});
```

Then set `sessions.driver` to `custom`. Keyring calls `replace()`, `revokeAll()` and `revokeDevice()`, and stores a new session, while holding the user's database row, so for one user those never run at the same moment and a driver doesn't have to guard them against each other. The contract's methods:

| Method | Does |
|---|---|
| `save($session)` | Stores a new `RegisteredSession`. It must never clear a revocation made in the meantime, or what a record was replaced by. |
| `find($id)` | The session, or `null`. |
| `forUser($user)` | The user's sessions that haven't expired, been revoked or been replaced, most recent first. A session is a user's by more than the ID: match on the record's `userType` (`RegisteredSession::typeOf($user)`, the connection and table the ID is one of) and its `userId`, here and in `revokeAll()` and `revokeDevice()`, or two user models with the same IDs would share sessions. `$session->belongsTo($user)` checks both. |
| `update($id, $changes)` | Changes only the named fields, such as `['lastActivityAt' => $now]` or `['assurance' => $level, 'expiresAt' => $at]`. Field names are as on `RegisteredSession`; `RegisteredSession::columns($changes)` turns them into snake case columns. Writing only these fields means a request can't write back a stale copy of the rest. |
| `revoke($id)` | Revokes one session. |
| `replace($id, $successor, $revoke = false)` | Moves a session to a new record: stores `$successor` and sets the old record's `replacedBy` and `replacedAt` (and revokes it, with `$revoke`). It only does so for a record that is neither revoked nor replaced, and returns whether it did. Of two calls for the same record at the same moment exactly one may return `true`, and the other's record must not be left behind: "remember me" being single use rests on this. The database driver uses one conditional `UPDATE` in a transaction, the cache driver the store's `add()`. |
| `revokeAll($user, $except = null)` | Revokes every session of the user but one. Returns how many, not counting replaced records. `Sessions::signOutEverywhere()` calls it, then also changes the remember token, stops trusting the other devices and cancels a pending email change, so call that one from your own code. |
| `revokeDevice($user, $deviceId)` | Revokes the user's sessions on one device. Returns how many. |
| `revokeEveryone()` | Revokes every user's sessions that signed in up to now, for [`keyring:sign-out --all`](#for-administrators). A session that is moving to a new record (`replace()`) as this runs must end up revoked there too, or "remember me" would carry it past the sign-out. The database driver revokes in rounds until none are left, and the cache driver, which can't list every user's records, keeps the moment and treats every session that signed in by then as revoked. |
| `prune()` | Deletes sessions that have expired or been revoked, for `keyring:prune`. Returns how many. A replaced record is kept until it expires, revoked or not: it's how a used "remember me" cookie is told from one that was never issued. A store that expires records itself can return `0`. |

### How Many Sessions

An account can be signed in 100 times at once (`sessions.max`). A sign in beyond that still succeeds, and ends whichever of the account's sessions has gone unused longest: its record is revoked, so that browser is signed out on its next request, with `revoked` as the reason. A session that has already [idled out](#timeouts) goes before one that can still be carried on.

```php
'sessions' => [
    'max' => 100,
],
```

Keyring ends the oldest session and never refuses the new sign in. Refusing would let whoever holds an account's sessions keep its owner out, and the owner couldn't even sign in to end them.

The number is a ceiling, not a rule about how many devices someone may use. It's twice [`devices.limit`](#devices), so each of the 50 devices an account keeps can have a session and one more it left behind by closing the browser, before anything still in use is ended. Without devices it's the only thing that stops one account filling the registry by signing in over and over. Lower it to allow fewer sessions at once (`1` for a single session, each sign in ending the last), or set it to `null` for no limit.

Only sessions count: not a record that was revoked, has expired, or that its session [moved on from](#the-session-registry). Sign ins for one account are counted one at a time, so two at the same moment can't both slip under the limit. A session your app starts with its own `Auth::login()` counts like any other.

### The Session Middleware

`Keyring\Http\Middleware\AuthenticateSession` does the checking. Keyring adds it to the `web` middleware group for you. Set `sessions.middleware` to `false` to add it yourself, under the alias `keyring.session`.

It only checks routes it runs on, and it needs Laravel's session to have started: a route that reads cookies and uses `auth` without `StartSession` lets a "remember me" cookie through with none of Keyring's checks. If signed-in sessions reach other groups, add `keyring.session` there too, or revoked and timed-out sessions keep working on those routes until Laravel's own session lifetime runs out. The usual case is Sanctum's stateful `api` routes for a single-page app:

```php
// bootstrap/app.php
->withMiddleware(function (Middleware $middleware) {
    $middleware->statefulApi();
    $middleware->appendToGroup('api', 'keyring.session');
})
```

The [conformance suite](testing.md#the-conformance-suite) checks this for you: it fails for any route that uses `auth` for Keyring's guard without `keyring.session`, and names it.

On each signed-in request it:

- signs the user out if their registry record was revoked, has expired, belongs to someone else, has been idle too long, or was [carried on by "remember me" somewhere else](#a-cookie-used-twice),
- registers sessions that started some other way, such as your own `Auth::login()` (on the response that signs in),
- carries a remembered session on when a ["remember me" cookie](#remember-me) signs its browser back in, or signs it out if that session has ended,
- runs the cheap [risk signals](risk.md#checkpoints),
- updates the last activity time, at most once a minute.

A second middleware, `keyring.password`, is added to the `web` group after it. It does nothing until a user is [held for a new password](protected-changes.md#requiring-a-password-change).

A session whose record has gone missing is signed out rather than registered again, so clearing records can't restart a session's window.

A signed-out request is sent to the login page with the `signed-out` status, and comes back to where it was going after signing in again. JSON clients get a `401` with `{"status": "signed-out", "message": "..."}`. Either way the response sends `Clear-Site-Data`, as signing out does, and `Keyring\Events\SessionEnded` is dispatched with the reason, logged as `session_ended`.

### "Remember Me"

Laravel's "remember me" cookie holds a token that is the same in every browser the user ticked it in, and nothing on the server makes it run out. On its own it would sign a browser back in for as long as the browser kept sending it, whatever had happened to the session it came with.

So a remembered sign in also sets a Keyring cookie holding that session's registry ID. It's httpOnly, `SameSite=Lax` and lasts as long as the record does. See [Keyring's Cookies](#keyrings-cookies) for its name and when it's `Secure`. When Laravel's cookie signs a browser back in, the middleware looks up the record that cookie names:

- If the record is the user's, hasn't been revoked, is inside its `absolute` limit, and was last used within `remember_idle`, the new session carries it on, under a new record and a new cookie. The new record is a copy of the old one with the same start and the same expiry, so coming back never starts the `absolute` limit again. Its device, IP address and browser are those of the request that came back, and its level starts from nothing: routes that need a level ask the user to verify. It's recorded like a sign in, so a browser the account hasn't used before is announced as a [new device](#new-device-sign-ins).
- Otherwise the request is signed out like any other ended session, with both cookies cleared: there was no Keyring cookie, its record is gone or was never issued (`expired`), or the record was revoked, timed out or belongs to someone else. A client that kept the cookies after a timeout or a risk response gets nowhere with them.

It's also refused while the account is [risk locked](risk.md#actions).

A session carried on this way dispatches `Keyring\Events\SessionResumed` and is logged as `session_resumed`, so the [security log](security-log-and-emails.md#entry-types) shows every time a browser was signed in, with a proof or without.

Your own `Auth::login($user, remember: true)` gets the Keyring cookie too, on the response that signs in, as long as that route has the middleware. A session given a new registry record (a mid-session [step-up](risk.md#actions), or `rotate()` on the `cookie` session driver) gets a new cookie for it.

If Laravel's cookie first reaches a route without the middleware, Laravel signs it in there and Keyring notes that in the session. The next request the middleware sees is checked the same way.

A remembered browser may stay away for longer than `idle`, up to `remember_idle` (14 days by default). [Timeouts](#timeouts) says why, and what it comes back to.

### A Cookie Used Twice

Each Keyring cookie works once. Coming back replaces the record it names and gives the browser a new cookie, so of two browsers holding the same pair, a copy and the one it was copied from, only the first to come back gets the session.

When the other one turns up, Keyring can't tell which of them is the owner, so the session ends for both:

- the request is signed out, with `reused` as the reason,
- the record the session has moved to since is revoked, however many times it was carried on, which signs the other browser out on its next request (`revoked`),
- `Keyring\Events\RememberMeReused` is dispatched with the `user` and the `session` that was ended, and logged as `remember_me_reused`, one of the default ["was this you?" alerts](security-log-and-emails.md#was-this-you-alerts).

That happens when a used cookie is sent again, and when a browser is still signed in on a record that "remember me" carried on somewhere else. If the session had already ended some other way, the request is just signed out and nothing is reported.

The user's remember token is left alone, so their other remembered browsers stay signed in: neither holder's cookies lead to a record that still works. To do more, such as sign the account out everywhere or ask for a new password, listen for the event:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\RememberMeReused;
use Keyring\Sessions\Sessions;

Event::listen(function (RememberMeReused $event) {
    app(Sessions::class)->signOutEverywhere($event->user);
});
```

A browser that comes back usually sends several requests at once, the page and whatever it loads alongside, all with the cookie the first of them uses up. So for a few seconds (`sessions.remember_grace`, 10 seconds by default) a request with the cookie that was just replaced joins the session the first one resumed, as long as it comes from the same browser (the same user agent). It gets the same new cookie and its own Laravel session pointing at the same record. It doesn't start another session, change the record or record a device, and the seconds count from when the cookie was replaced, so sending it again doesn't keep it alive. A used cookie from a different browser counts as used twice, however soon it comes.

A shorter time leaves less room for a copy to slip in next to the owner, and more chance that a slow request of the owner's own ends their session. Set it to `0` only if a browser's requests never overlap.

## Keyring's Cookies

Keyring sets two cookies of its own: the device cookie, and the one that ties ["remember me"](#remember-me) to its session. What they're called depends on how your app is served:

| Your app | Device cookie | "Remember me" cookie |
|---|---|---|
| Served over HTTPS | `__Host-known_device` | `__Host-remembered_session` |
| Served over HTTPS, with `session.domain` set or `session.path` other than `/` | `__Secure-known_device` | `__Secure-remembered_session` |
| Served over plain HTTP, as on `http://localhost` | `known_device` | `remembered_session` |

The names say what each cookie is for and not what set it. OWASP's Session Management Cheat Sheet asks that of cookie names, because one that names the software behind it tells an attacker what to look up. Laravel's session cookie is yours to name (`SESSION_COOKIE`): see [Secure Cookies](security.md#secure-cookies).

Keyring takes your app to be served over HTTPS when `APP_URL` starts with `https://`, or when `session.secure` (`SESSION_SECURE_COOKIE`) is `true`. It goes by those settings and not by the request, because the name has to be the same on every request, and behind a proxy your app doesn't [trust](security.md#what-your-app-must-provide) every request looks like plain HTTP.

Over HTTPS both cookies are always `Secure`. A browser only accepts a `__Host-` cookie that is `Secure`, has `Path=/` and no `Domain`, so another subdomain, or a page loaded over plain HTTP, can't set or replace it. A cookie shared with subdomains can't have that prefix, so Keyring falls back to `__Secure-`, which only promises that the cookie was set over HTTPS. Over plain HTTP a browser refuses both prefixes, so the plain names are used, and the cookies are `Secure` whenever the request itself came over HTTPS.

To use names of your own, set `devices.cookie` and `sessions.remember_cookie`. Keyring uses a name you set exactly as it is, still `Secure` over HTTPS, and it's up to you to give it a prefix.

A browser that was given the plain cookies before your app moved to HTTPS keeps its device and its remembered session. While it holds no cookie under the new name, Keyring reads the plain one. The next time that browser signs in, or "remember me" brings it back, it gets the cookie under the new name and the plain one is deleted. Anything on your domain could have set a plain cookie, so one is only ever used to find a device the account already has, never to start a new one.

## For Administrators

Whoever runs the app can end sessions without waiting for them to time out.

```bash
php artisan keyring:sign-out 42
php artisan keyring:sign-out taylor@example.com
php artisan keyring:sign-out --all
```

**One user** is named by ID or by username (the `username` attribute, typed however they would type it). The command says who it signed out and how many sessions ended. It does what `Sessions::signOutEverywhere($user)` does: every session is revoked, the "remember me" token is changed, no device stays trusted and a pending email change is cancelled, so nothing gets back in without signing in. It dispatches `SessionsRevoked`, logged as `sessions_revoked`. If the name is one user's ID and another's username, nobody is signed out and the command names both: run it again with `--id` and the ID of the one you mean.

**Everyone** takes `--all`, and asks first unless you pass `--force`. Every session that signed in up to that moment ends, whichever record it's on, and a browser is signed out on its next request. "Remember me" brings none of them back: a cookie is only good for the session it names, and a session that was being carried on at that very moment is ended on the record it moved to. People can sign in again straight away. It only ends sessions. Trusted devices, "remember me" tokens and pending email changes are left as they are, since everyone being signed out says nothing about any one account.

From your own code, for an admin screen say:

```php
use Keyring\Contracts\SessionRegistry;
use Keyring\Facades\Keyring;
use Keyring\Sessions\Sessions;

app(Sessions::class)->signOutEverywhere($user);   // one user, returns how many sessions ended

app(SessionRegistry::class)->revokeEveryone();    // everyone

Keyring::unlock($user);                           // let a locked-out user try again
```

`Keyring::unlock()` is the other half of looking after an account: it lifts a [risk lock](risk.md#actions) and the [sign-in lockouts](security.md#rate-limiting) on it, as a completed password reset does. To keep someone out for good, use [`Keyring::allowSignInWhen()`](sign-in-flow.md#who-may-sign-in) and call `signOutEverywhere()` as you set your flag: by itself the gate ends the account's sessions when the first of them next makes a request.

Like every sign-out that isn't the browser's own, these take effect on a session's next request [where the session middleware runs](#the-session-middleware).

## Timeouts

```php
'sessions' => [
    'idle' => '2h',
    'remember_idle' => '14d',
    'absolute' => '30d',
    'levels' => [
        'aal2' => ['idle' => '1h', 'absolute' => '24h'],
        'aal3' => ['idle' => '15m', 'absolute' => '12h'],
    ],
    'end_on_lapse' => false,
],
```

- **`idle`** ends a session after this much inactivity: two hours by default, the lifetime of Laravel's own session in a new app. Keyring counts it on the registry record, so it holds whatever your session driver and `session.lifetime` are, and a session that idled out can't be picked up again. `null` leaves inactivity to Laravel's session lifetime alone.
- **`remember_idle`** is the same limit for a browser that ticked ["remember me"](#remember-me): 14 days by default. `null` lets it stay away for the whole `absolute` limit.
- **`absolute`** ends a session this long after sign in, however active it is. A browser that comes back on ["remember me"](#remember-me) carries the same session on, under a new record with the same expiry, so that doesn't start the limit again. The browser is asked to keep Laravel's "remember me" cookie no longer either, unless you set your guard's `remember` (in minutes) yourself. That only changes how long the browser holds it: it still stops working when its session ends.
- **`levels`** are how long each [assurance level](policies.md#assurance-levels) keeps counting (`aal1`, `aal2` or `aal3`). The defaults are NIST SP 800-63B-4's reauthentication limits (Sec. 2.2.3 and 2.3.3).
- **`end_on_lapse`** ends a session when the level it signed in at runs out. See [below](#ending-a-session-with-its-level).

#### Inactivity and "Remember Me"

Ticking "remember me" asks to stay signed in on that browser between visits, so the two-hour limit can't apply to it: every remembered browser would be asked to sign in again after an afternoon away, and the box would do nothing. Keyring decides it this way instead:

- A remembered session isn't ended by `idle`. It's ended by `remember_idle`, 14 days without a request, and by `absolute`, 30 days after the sign in, which coming back never restarts.
- Once it has been unused for `idle`, it keeps nothing it proved. A browser that comes back on its cookies starts with no level at all, and one whose Laravel session outlived the two hours has every level lapsed. Either way, routes behind [`keyring:aal2`](step-up.md#raising-assurance) or [`keyring.fresh`](step-up.md#fresh-verification) ask the user to verify again, and so do Keyring's own routes for changing how someone signs in.
- So a remembered browser left unattended still opens whatever sits behind `auth` alone. Put anything that shouldn't be reachable that way behind a level or a fresh verification, or don't offer "remember me": leave the `remember` field off your login form, or set `remember_idle` to the same as `idle`. NIST SP 800-63B-4 (Sec. 5.1) doesn't take a cookie in place of authentication at all, so an app that follows it leaves the checkbox out: see [Known Limitations](security.md#where-keyring-departs-from-a-standard).

Set `remember_idle` no shorter than `idle`, or ticking the box would sign people out sooner.

A level lapses on its own clock without ending the session: after its `idle` without a request, or its `absolute` after the verifications that reached it, however active the session is. The user stays signed in at whatever level is left, and routes that need the lapsed level ([`keyring:aal2`](step-up.md#raising-assurance)) ask them to verify again. Once inactivity has lapsed a level, every factor for it is asked for again, not just the missing one: nothing verified before the lapse counts toward it, wherever the user verifies next. Verifying again restarts the idle clock.

### Ending a Session With Its Level

NIST SP 800-63B-4 (Sec. 5.2) says a session is terminated when its inactivity or overall timeout passes. It also lets a session be treated as a lower level than it was authenticated at (Sec. 5.1), and that's what Keyring does by default: a session that signed in with two factors stops being AAL2 after an hour idle or 24 hours, and carries on as the AAL1 session its password alone would have started, under `idle` and `absolute`. Nothing behind `keyring:aal2` or `keyring.fresh` is reachable meanwhile. It's the default because ending those sessions would sign out the people who set up a second factor after an hour away, and leave everyone who didn't signed in for 30 days.

That isn't enough where the whole app is meant to be AAL2, or where you want NIST's wording to the letter. Turn the lapse into the end of the session:

```php
'sessions' => [
    'end_on_lapse' => true,
],
```

- A session ends on the first request after the level it **signed in at** runs out: after that level's `idle` without a request, or its `absolute` after the factors were proved. The user is signed out as for any other timeout, with the reason `idle` or `expired` on `SessionEnded`.
- Proving every factor for that level again before then (any [step-up](step-up.md) that asks for them all) starts both limits over, as reauthenticating does in NIST.
- A level reached later by a step-up still lapses on its own and takes nothing with it. A session that signed in with a password and stepped up for one page stays an AAL1 session.
- A [risk response](risk.md#responding-to-risk) that asks a signed-in session to step up ends it too: forgetting what the session proved is its level running out. The reason on `SessionEnded` is `risk`.
- "Remember me" brings nothing back. Its cookie proves nothing, so there's no level for the session to carry on at: the browser signs in again. NIST doesn't accept such a cookie in place of authenticating either (Sec. 5.1), so leave the checkbox off your login page.
- The timeouts leave sessions signed in at AAL1 as they were: `idle` and `absolute` already end those.

[Recipes](recipes.md#an-app-whose-every-page-needs-aal2) has the full setup for an app whose every page needs AAL2.

## Pruning

`php artisan keyring:prune` deletes what Keyring no longer needs:

- devices revoked more than 30 days ago, or not seen for a year (`devices.keep_revoked_for` and `devices.keep_unseen_for`),
- email changes that ended (expired, cancelled, reverted, or past their revert window) more than 30 days ago (`email_changes.keep_ended_for`), since they hold both addresses,
- security log entries older than `security_log.keep_for`,
- registered sessions that have expired or been revoked, through the registry's `prune()`. A record "remember me" replaced stays until it would have expired, so its cookie is still recognised as used. The cache driver's records expire on their own.

Keyring adds it to Laravel's scheduler itself, every day at 03:00, so it runs wherever your app's `schedule:run` does and nothing is kept past its time because a line was left out of `routes/console.php`. `php artisan schedule:list` shows it. To run it at another time, change `prune_at`:

```php
// config/keyring.php
'prune_at' => '01:30',
```

Set it to `null` and Keyring schedules nothing, which leaves it to you: on one server only, say, or from a job of your own.

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('keyring:prune')->daily()->onOneServer();
```

Either way it only runs if your server runs Laravel's scheduler (`* * * * * php artisan schedule:run`), as any scheduled task does.

It runs Laravel's `model:prune` for Keyring's models, including your own [device model](#your-own-device-model). Laravel's plain `model:prune` only looks in `app/Models`, so it won't find them on its own.

## Events

In `Keyring\Events`:

| Event | Properties |
|---|---|
| `NewDeviceSignedIn` | `user`, `device`, and `revokeUrl($days = null)` |
| `DeviceRevoked` | `user`, `device`, `reported` (whether it came from the "this wasn't me" link) |
| `SessionsRevoked` | `user`, `count`: after signing out everywhere else, ending one session, an administrator's `keyring:sign-out` for one user, or the first request refused for an account the app keeps out |
| `RememberMeReused` | `user`, `session` (the `RegisteredSession` that was ended) |
| `SessionResumed` | `user`, `session` (the `RegisteredSession` a remembered browser carries on as) |
| `AccessRefused` | `user`, `resource` (`device`), `id`: a request to sign out a device that isn't the user's, answered with a 404 |
| `LinkRefused` | `link` (the route's name), `reason` (`signature` or `expired`): a "this wasn't me" link that was refused |
