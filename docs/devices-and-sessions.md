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
- [The Session Registry](#the-session-registry)
    - [Drivers](#drivers)
    - [Writing a Driver](#writing-a-driver)
    - [The Session Middleware](#the-session-middleware)
- [Timeouts](#timeouts)
- [Pruning](#pruning)
- [Events](#events)

## Introduction

Keyring tracks two things:

- **Devices**: browsers the user has signed in from, recognised by a cookie. A device is an input to your policy and to risk signals. It's never a factor.
- **Sessions**: each signed-in session, kept in Keyring's own registry so they can be listed and revoked whatever session driver Laravel uses (database, file, cookie or cache).

## Routes

| Method | URI | Name | Middleware | Does |
|---|---|---|---|---|
| `GET` | `/user/devices` | `keyring.devices.index` | `auth:{guard}` | Lists the user's devices as JSON. |
| `DELETE` | `/user/devices/{id}` | `keyring.devices.destroy` | `auth:{guard}`, `manage_middleware` | Signs one device out. |
| `DELETE` | `/user/devices` | `keyring.devices.destroy-others` | `auth:{guard}`, `manage_middleware` | Signs out every other session. |
| `GET` | `/devices/{id}/report` | `keyring.devices.report` | signed, `keyring` limiter | The "this wasn't me" link: a page with a button. |
| `POST` | `/devices/{id}/report` | `keyring.devices.report.store` | signed, `keyring` limiter | Signs the device out. |

## Devices

On every sign in, Keyring looks for its device cookie (`keyring_device` by default). If it's missing or unknown, Keyring creates a device with a new random token and sets the cookie. The cookie is httpOnly, `SameSite=Lax`, secure when `session.secure` is on, and lasts 400 days. Only a SHA-256 hash of the token is stored.

Each device records a readable name built from the user agent (the browser and the operating system, as in ":browser on :platform"), the last IP address and location, and when it was first and last seen. The user agent is never a factor. It's only a weak risk signal: `SessionFingerprintChanged` notices when a session's browser or platform changes.

A browser shared by several accounts has one cookie and a device for each account that signed in on it.

### Trusted Devices

When `devices.trust_for` isn't `null`, the challenge page offers "don't ask again on this device" (`canTrustDevice`). Posting `trust: true` with the verification marks the device trusted for that long (30 days by default).

Trust on its own changes nothing. It's for your [policy](policies.md#deciding-per-user-and-attempt) to use:

```php
Keyring::require(fn (User $user, Attempt $attempt) => $attempt->device()?->isTrusted()
    ? Requirement::aal1()
    : Requirement::aal2()->ifEnrolled());
```

Revoking a device stops trusting it. Signing out everywhere else, including after a password change, stops trusting every other device. A password reset, a reverted email change and a critical risk sign out everywhere, so they stop trusting every device.

### New Device Sign Ins

A sign in from a new device dispatches `Keyring\Events\NewDeviceSignedIn`. Turn on the `new_device` [security email](security-log-and-emails.md#security-emails), or send your own:

```php
use Illuminate\Support\Facades\Event;
use Keyring\Events\NewDeviceSignedIn;

Event::listen(function (NewDeviceSignedIn $event) {
    $event->user->notify(new NewSignIn($event->device->description(), $event->revokeUrl()));
});
```

`$device->description()` adds the place when it's known, as in ":browser on :platform near :city".

### The "This Wasn't Me" Link

`$event->revokeUrl()` (or `$device->revokeUrl($days)`) returns a signed link to `GET /devices/{id}/report`, valid for 7 days by default. Opening it shows the `device-report` page (props: `device`, a description such as "Chrome on macOS", and `url`), whose button POSTs back to the same signed URL. That revokes the device without the user signing in: its sessions end, it stops being trusted, and every "remember me" cookie for the user stops working. The user lands on the login page with a message recommending a password change. The event is logged as `device_reported`, which shows as a ["was this you?" alert](security-log-and-emails.md#was-this-you-alerts) at their next sign in.

The link is built from `APP_URL`, and its signature covers only the path and query, so a forged `Host` header can't point it at another site. Like the email change links, opening it changes nothing, so mail scanners that open links can't sign anyone out.

### Locations

Keyring asks a locator class for each request's rough location. The default `Keyring\Devices\NullLocator` knows nothing, so locations are empty and the location [risk signals](risk.md) stay quiet.

To turn locations on, set `devices.locator` to a class implementing `Keyring\Contracts\LocatesIps`:

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
use Keyring\Devices\UserAgent;

UserAgent::describeUsing(fn (string $userAgent) => app(UserAgentParser::class)->parse($userAgent)->summary());
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

`GET /user/devices` returns the user's devices that haven't been revoked, most recently seen first:

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

`DELETE /user/devices` signs out every session except the current one, changes the "remember me" token, and stops trusting every other device. It responds with `sessions-revoked`. Do the same from your own code with `Keyring\Sessions\Sessions::revokeAll()`, which returns how many sessions it revoked:

```php
use Keyring\Sessions\Sessions;

app(Sessions::class)->revokeAll($user, except: app(Sessions::class)->current($request)?->id);
```

Laravel keeps one "remember me" token per user, so changing it signs out every remembered browser at once, including the current one the next time its session ends.

## The Session Registry

Every signed-in session gets a record in Keyring's registry, with its own random ID, the user, the device, the assurance level, the IP address, the user agent, and its timestamps. Laravel's session ID is never stored. The registry ID lives inside the session.

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

Then set `sessions.driver` to `custom`. The contract's methods:

| Method | Does |
|---|---|
| `save($session)` | Stores a new `RegisteredSession`. It must never clear a revocation made in the meantime. |
| `find($id)` | The session, or `null`. |
| `forUser($user)` | The user's sessions that haven't expired or been revoked, most recent first. |
| `update($id, $changes)` | Changes only the named fields, such as `['lastActivityAt' => $now]` or `['assurance' => $level, 'expiresAt' => $at]`. Field names are as on `RegisteredSession`; `RegisteredSession::columns($changes)` turns them into snake case columns. Writing only these fields means a request can't write back a stale copy of the rest. |
| `revoke($id)` | Revokes one session. |
| `revokeAll($user, $except = null)` | Revokes every session of the user but one, cycles the remember token and stops trusting the other devices. Returns how many. |
| `revokeDevice($user, $deviceId)` | Revokes the user's sessions on one device. Returns how many. |
| `prune()` | Deletes sessions that have expired or been revoked, for `keyring:prune`. Returns how many. A store that expires records itself can return `0`. |

### The Session Middleware

`Keyring\Http\Middleware\AuthenticateSession` does the checking. Keyring adds it to the `web` middleware group for you. Set `sessions.middleware` to `false` to add it yourself, under the alias `keyring.session`.

On each signed-in request it:

- signs the user out if their registry record was revoked, has expired, belongs to someone else, or has been idle too long,
- registers sessions that started some other way, such as a "remember me" cookie,
- runs the cheap [risk signals](risk.md#checkpoints),
- updates the last activity time, at most once a minute.

A session whose record has gone missing is signed out rather than registered again, so clearing records can't restart a session's window.

A signed-out request is sent to the login page with the `signed-out` status, and comes back to where it was going after signing in again. JSON clients get a `401` with `{"status": "signed-out", "message": "..."}`.

## Timeouts

```php
'sessions' => [
    'idle' => null,
    'absolute' => '30d',
    'levels' => [
        'aal3' => ['idle' => '15m', 'absolute' => '8h'],
    ],
],
```

- **`idle`** ends a session after this much inactivity. `null` leaves it to Laravel's session lifetime.
- **`absolute`** ends a session this long after sign in, however active it is.
- **`levels`** override either for sessions at an assurance level: `none`, `aal1`, `aal2` or `aal3`.

A session takes the level it reached at sign in. If [step-up](step-up.md) raises it, the session takes the new level's idle timeout, and its absolute timeout can get shorter (never longer), still counted from sign in.

## Pruning

`php artisan keyring:prune` deletes what Keyring no longer needs:

- devices revoked more than 30 days ago,
- email changes that ended (expired, cancelled, reverted, or past their revert window) more than 30 days ago, since they hold both addresses,
- security log entries older than `events.keep_for`,
- registered sessions that have expired or been revoked, through the registry's `prune()`. The cache driver's records expire on their own.

Schedule it daily:

```php
// routes/console.php
use Illuminate\Support\Facades\Schedule;

Schedule::command('keyring:prune')->daily();
```

It runs Laravel's `model:prune` for Keyring's models, including your own [device model](#your-own-device-model). Laravel's plain `model:prune` only looks in `app/Models`, so it won't find them on its own.

## Events

In `Keyring\Events`:

| Event | Properties |
|---|---|
| `NewDeviceSignedIn` | `user`, `device`, and `revokeUrl($days = 7)` |
| `DeviceRevoked` | `user`, `device`, `reported` (whether it came from the "this wasn't me" link) |
| `SessionsRevoked` | `user`, `count` |
