# Upgrade Guide

This guide lists anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

## Unreleased

### Published Config

If you published `config/keyring.php`, you may add `'pages' => true`, `'authenticator_changes' => ['established_after' => '7d', 'skip_with_totp' => false]` and `'authenticators_url' => null`. Leaving them out is the same. Set `authenticators_url` to your page for sign-in methods, so the emails about a new one link there.

### Frozen Sign-In Methods

Keyring has a new table, `keyring_sign_in_changes`. Run `keyring:install` again to publish the migration, then run it:

```bash
php artisan keyring:install
php artisan migrate
```

Until you do, removing an established sign-in method and replacing recovery codes fail with a database error.

An authenticator is now [established](docs/authenticators.md#established-authenticators) once the account has had it for `authenticator_changes.established_after`, 7 days by default. Authenticators added before the upgrade go by when they were added, so most are established already. Three things change:

- `noDowngrade()` only asks for a passkey or security key once the account has an established one. A user who added their first key in the last 7 days can still sign in with their password and authenticator app until it's established.
- A fresh verification only asks for a key that can't leave its device when that key is established.
- An account's sign-in methods are [frozen](docs/authenticators.md#frozen-sign-in-methods) while it has an authenticator that isn't established, and for 7 days after it removes or replaces an established one, or recovery codes that had codes left. While frozen, removing an established authenticator and replacing recovery codes get a `422` on `authenticator`. A settings page that shows validation errors on `authenticator` shows the message, which says how long is left. JSON also has `frozen`, with `reason`, `until` and `skip`. When `skip` names a key factor, your page can offer to [make the change with that key](docs/authenticators.md#making-a-change-with-an-established-key), using `proveWithKey()` from `@keyringjs/keyring`.

If your support tools remove authenticators or replace recovery codes for users, pass `ignoreFreeze: true` to `AuthenticatorChanges::remove()` or `add()`. A subclass that overrides either needs the new argument too.

`AuthenticatorRemovalRefused` has a new `reason` property, and its log entry has `reason` in `meta`. `EnrollmentRefused` can have the reason `frozen`.

In your tests, an authenticator made with `Authenticator::factory()` was added just now, so it isn't established. A test that makes a passkey and expects `noDowngrade()` to ask for it, or that removes an authenticator or replaces recovery codes while one like that is there, needs `->established()` on the factory:

```php
Authenticator::factory()->passkey()->established()->for($user, 'authenticatable')->create();
```

To turn the freeze off, set `authenticator_changes.established_after` to `0`. That brings back the lockout it prevents.

### Pages Asked For With JSON or an XHR

A request for one of Keyring's pages that expects JSON, and isn't an Inertia visit, now gets `{"page": "...", "props": {...}}`. It used to get the Inertia root view, or the Blade view, as HTML. Laravel counts a request as expecting JSON when it sends `Accept: application/json`, and also when it's an XHR (`X-Requested-With: XMLHttpRequest`) that accepts anything (`Accept: */*` first, or no `Accept` at all). So a Blade page that loads `/login` or another of Keyring's pages with jQuery's `$.get()` or `$.ajax()`, or another library that sends that header, now gets JSON instead of the view's HTML. Ask for HTML with `Accept: text/html`, or render the page with a closure through `Keyring::page`, which still answers as it did. Inertia visits still get the component.

### JSON Answers

These only matter to code that reads Keyring's JSON, such as tests that compare whole bodies with `assertExactJson`.

- The challenge response, the `423` for step-up, and a status response whose `redirect` is one of Keyring's pages have a new `page` key. The `401` for a session Keyring ended has new `page` and `redirect` keys. See [Responses](docs/sign-in-flow.md#responses).
- A JSON request to a sign in or step-up that ran out, or used up its code guesses, gets a `422` with the error, `page` and `redirect`, where it used to be redirected to the login or confirm page.
- The default `VerifiedResponse` answers JSON requests with `{"status": "email-verified", "message": "...", "justNow": ..., "redirect": "..."}`, where it always redirected. A response of your own bound with `Keyring::respondWith` is unchanged.

The new `email-verified` status has its message in `lang/en/status.php`. If you published Keyring's translations, Keyring's English line is used until you add `'email-verified'` to yours.

### Detours Keep the Requirement

Only apps that extend these classes need to change anything:

- `StepUp::enrollFirst()` takes an optional `?Requirement $requirement` as its third argument, and `Detours::remember()` one as its fourth. A subclass that overrides either needs that argument too.
- `Detours::put()` keeps its arguments. It saves the requirement from `$this->requiring` beside the page, so an override that calls the parent needs no change. One that writes to the session itself saves pages without a requirement, which come back with the next sign-in method added, as before. So does a subclass that overrides `remember()` and calls `put()` itself rather than the parent's `remember()`, since only the parent's `remember()` sets `$this->requiring`.
- `Detours::pull()` leaves a page saved, and returns `null`, while the signed-in account can't meet the requirement saved with it.

### The XSRF Token Stays on Your Origins

The browser package's `json()` no longer sends `X-XSRF-TOKEN` to a full URL on another origin. It sends it to the page's own origin, and to the `baseUrl` set with [`configureRequests()`](docs/frontend.md#frontends-on-another-origin). If you called Laravel on another origin by passing `json()` full URLs, set `baseUrl` to that origin instead and pass paths.

## From 0.2 to 0.3

### Run the New Sessions Migration

Session records have a new `origin` column. It names the record a session started on, which lets the session keep its handle when it moves to a new record. Run `keyring:install` again to publish the migration, then run it:

```bash
php artisan keyring:install
php artisan migrate
```

`keyring:install` only adds the migrations you don't have yet, and it leaves your config and provider alone. You may copy `database/migrations/*_add_origin_to_keyring_sessions_table.php` from the package instead. The migration uses `sessions.table` and `sessions.connection` from your config.

On the `database` driver, every session move fails until you do. Signing in still works, but a browser that "remember me" brings back, a risk response that asks a session to verify again, and a step-up on the `cookie` session driver all fail with a database error. The `cache` driver needs no migration.

Existing rows need nothing. A record with no `origin` is the record its session started on, so sessions keep the handles they had.

During a rolling deploy, or after a rollback, a server still on the old code that moves a session gives the new record no `origin`. That session's handle changes once.

### Custom Session Registry Drivers

A [driver of your own](docs/devices-and-sessions.md#writing-a-driver) should store `origin` with the rest of a record and return it from `find` and `forUser`. If you store `$session->toArray()` and read it back with `RegisteredSession::fromArray()`, it already does. If yours writes that array into a table of its own, add a nullable `origin` column before you deploy: the array has a new key, and every sign in fails on a table without it. A driver that drops `origin` still works, but its sessions get a new handle every time they move. The [conformance suite](docs/testing.md#the-conformance-suite) has a check for this.

### Session Registry Drivers

A custom session registry driver, and anything that decorates `Keyring\Contracts\SessionRegistry`, must now return the records it revoked:

```php
// Before
public function revoke(string $id): void;
public function revokeAll(Authenticatable $user, ?string $except = null): int;
public function revokeDevice(Authenticatable $user, string $deviceId): int;

// After
public function revoke(string $id): ?RegisteredSession;
public function revokeAll(Authenticatable $user, ?string $except = null): Collection;  // Collection<int, RegisteredSession>
public function revokeDevice(Authenticatable $user, string $deviceId): Collection;  // Collection<int, RegisteredSession>
```

`revoke()` returns the record as it now stands, with `revokedAt` set, or `null` when it revoked nothing: no such record, or one revoked already. `revokeAll()` and `revokeDevice()` return every record they revoked, which on the database driver may include records that had expired but were never revoked. A driver may also return a record another call ended at the same moment, but never leave out one it revoked. Which records Keyring's drivers revoke is unchanged. Where your code used the count they returned, use `->count()`. `Sessions::signOutEverywhere()` and `Sessions::revokeDevice()` still return a count, as does the `SessionsRevoked` event; with a driver that reports a record twice, it may count a session another call ended at the same moment. The conformance suite checks the configured driver. See [Writing a Driver](docs/devices-and-sessions.md#writing-a-driver).

### The Session Registry Is Wrapped

Every session registry driver, Keyring's and yours, now comes wrapped in `Keyring\Sessions\AnnouncingSessionRegistry`, which dispatches a `RegisteredSessionEnded` for each session that ends. `app(SessionRegistry::class)` and `Sessions::registry()` return the wrapper, not the driver. Code that checked for a driver's class, such as `instanceof DatabaseSessionRegistry`, or that called a method of your own driver that isn't on the contract, should call `->inner()` to get the driver:

```php
// Before
$driver = app(SessionRegistry::class);

// After
$driver = app(SessionRegistry::class)->inner();
```

A custom driver registered with `SessionRegistryManager::extend()` needs no change. One you bind in the container as `SessionRegistry` yourself isn't wrapped, so nothing it ends is announced, and the new conformance check fails. Register it through the manager instead. See [Writing a Driver](docs/devices-and-sessions.md#writing-a-driver).

A session you revoke by writing `revokedAt` with `save()` or `update()` isn't announced. Revoke it with `revoke()`.

If a subclass of `Keyring\Http\Middleware\AuthenticateSession` overrides `signOut()` without calling the parent, the sessions it ends are announced as `revoked`. Call `parent::signOut()`, or end them inside `app(Sessions::class)->because($reason, fn () => ...)`. A reason of your own passed to `signOut()` still reaches `SessionEnded` as it is, and the new event gets `revoked`.

The contract's methods mark the parameters that hold a registry ID with `#[\SensitiveParameter]`. A driver without the attribute still works, but its stack traces show those IDs. Adding it is recommended.
### Published Config

If you published `config/keyring.php`, you may add `'continue_as_guest' => []` and `'sweep_limit' => 1000` to `sessions`, and `'unlisted' => []` to `security_log`. Leaving any of them out is the same as those values.

### Guests on Step-Up Routes

`keyring:{level}` now sends a guest to sign in even when their session still holds what the last user proved, as `keyring.fresh` already did. A session keeps that when the guard can no longer load its user, say because the account was deleted, and a guest used to get through on it wherever the middleware wasn't placed after `auth`. Routes that place it after `auth`, as [Step-Up](docs/step-up.md#introduction) asks, see no change.

### Extending Step-Up

These only matter if you extend or rebind `Keyring\Login\StepUp` or `Keyring\Sessions\SessionAssurance`, or extend Keyring's step-up middleware.

- `StepUp`'s constructor also takes a `Keyring\Devices\DeviceManager`, after the `KeyringManager`. A subclass that calls `parent::__construct()` must pass it.
- What `keyring.fresh` asks for moved from `RequireFreshVerification` to `StepUp::freshRequirement()`. The middleware's protected `requirement()` and `strongest()` methods are gone, so overriding them on a subclass of the middleware no longer has any effect. Override `freshRequirement()` or `strongest()` on `StepUp` instead.
- `RequireAssurance` and `RequireFreshVerification` now only have the `$stepUp` property. The `$assurance`, `$keyring`, and `$devices` properties are gone, and the decisions they made are `StepUp::unlessReached()` and `StepUp::unlessFresh()`. Each one asks a protected check first, `reached()` or `verifiedSince()`, and `StepUp::meets()` asks the same checks. To change what counts, override the checks, so `meets()` keeps giving the same answer as the middleware.
- Both middleware constructors now take only the `StepUp`. A subclass that calls `parent::__construct()` with the old arguments must pass just that.
- `SessionAssurance::level()` and `countingToward()` take an optional `int $since = 0`. A subclass that overrides either must add it, or PHP won't load the class.

### Detours

Only apps that extend or build these classes themselves need to change anything:

- `Keyring\Login\StepUp`, `Keyring\Login\SignIn` and `Keyring\Http\Middleware\RequirePasswordChange` take a `Keyring\Login\Detours` as a new last constructor argument. Built by the container, they get it on their own. If you call `new` on one, pass `app(Detours::class)`.
- `StepUp::enrollFirst()` takes an optional `?string $continue` as its second argument. A subclass that overrides it needs that argument too.
- `PasswordController::update()` has two new injected arguments at the end, `PasswordHolds $holds` and `Detours $detours`. A subclass that overrides it needs them too.

### Queued Listeners

This only matters if you queue listeners for Keyring's events. Some events are now serialised differently, so they don't put registry IDs, password hashes, or secrets on your queue. See [Events](docs/events.md).

Restart your queue workers with the deploy. A worker still running the old code can't restore the jobs the new one queues.

Jobs the old version queued still run under the new one. An event that carries an `attempt` (`Authenticated`, `Confirmed`, `FactorChallenged`, `FactorVerified`, `VerificationRefused`) restores, and its attempt looks its user up again. A `FactorChallenged` or `FactorVerified` for an unsaved authenticator, such as the password's, queued by the old version still fails, as it did before, since it went by an ID that was never stored. The new version queues an unsaved authenticator as it is, so those run (see [Events](docs/events.md)). A job for `SessionResumed` or `RememberMeReused` restores without a `handle`, and reading it throws, so drain those first only if a listener for them starts reading `$event->handle` in the same deploy.

Then prune `failed_jobs` of these events. Rows queued before the upgrade still hold session registry IDs and users' password hashes and remember tokens. If you run Horizon, it keeps its own copy of failed jobs in Redis, payload included, for `trim.failed` minutes (a week by default) and shows them on its dashboard. Pruning `failed_jobs` leaves those, so forget them in Horizon too. `php artisan horizon:forget <id>` forgets one, and `--all` forgets every failed job in both Horizon and `failed_jobs`, not only these events.

A queued listener for `SessionResumed` or `RememberMeReused` now gets the session without its registry IDs: a blank `id`, and a null `replacedBy` and `origin`. Code that used them does nothing now. For example, `Sessions::revoke($user, $event->session)` won't find the session, and `Sessions::handle($event->session)` throws a `LogicException`. Use the event's `handle` instead, which is always set:

```php
use Keyring\Events\SessionResumed;
use Keyring\Sessions\Sessions;

public function handle(SessionResumed $event): void
{
    $sessions = app(Sessions::class);

    if ($session = $sessions->find($event->user, $event->handle)) {
        $sessions->revoke($event->user, $session);
    }
}
```

Listeners that aren't queued see both events as before.

A queued listener for `AuthenticatorRemoved` now gets the user fetched again by ID, as with every other event, so the job fails with a `ModelNotFoundException` if the user was deleted before it ran. The authenticator comes without its `secret`.

### Sweeping Ended Sessions

A new migration adds `announced_at`, `end_reason`, `announce_attempts`, and `announce_after` to `keyring_sessions`, with three indexes for the sweep. Run `keyring:install` again to publish it, then migrate:

```bash
php artisan keyring:install
php artisan migrate
```

It marks every session revoked before it as announced, so the first sweep doesn't announce them again. Pruning keeps only the last day's revocations, so that's usually a small update. On a large table, plan for it: if pruning has never run, it touches every revoked row, and on PostgreSQL creating the indexes blocks writes to the table while they build.

Until it has run, everything works as before: sessions end and are announced, and Keyring logs a warning, once a day, that the columns are missing. `keyring:sweep` refuses to run, and `keyring:prune` deletes as it always has. The conformance suite has a check that fails until you migrate. Once it has run, Keyring starts noting announcements within five minutes, long-lived processes such as Octane and queue workers included. If you roll the migration back, it can take up to five minutes to be noticed under FPM, and Octane and queue workers that found the columns don't notice until they restart. Until then a sign-out that finds the columns gone is made again without them, so signing out keeps working. The `cache` driver needs no migration, and has nothing to sweep.

Once the migration has run, `keyring:prune` changes, whether or not you turn the sweep on: it no longer deletes a session that has expired but that nothing ended until a day after its expiry, or one that was revoked but not yet announced until the sweep gives up on it a day later. It also keeps a session the sweep ended for timing out as long as it would have kept it unended, until a day after its expiry, so a browser that comes back is still told it timed out. So an expired record that nobody ended lives up to a day longer, and so does one the sweep ended.

The sweep is off until you set `sessions.sweep_every`.

A custom driver keeps working, and `keyring:sweep` says it has nothing to sweep.

`RegisteredSessionEnded` may now repeat for the same handle. Make listeners idempotent by handle.

## From 0.1 to 0.2

There's nothing to change. The new `CredentialStuffing` risk signal is off until you add it to your provider.
