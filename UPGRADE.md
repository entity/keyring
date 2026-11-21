# Upgrade Guide

This guide lists anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

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

### Published Config

If you published `config/keyring.php`, you may add `'continue_as_guest' => []` to `sessions`. Leaving it out is the same as an empty list.

### Extending Step-Up

These only matter if you extend or rebind `Keyring\Login\StepUp` or `Keyring\Sessions\SessionAssurance`, or extend Keyring's step-up middleware.

- `StepUp`'s constructor also takes a `Keyring\Devices\DeviceManager`, after the `KeyringManager`. A subclass that calls `parent::__construct()` must pass it.
- What `keyring.fresh` asks for moved from `RequireFreshVerification` to `StepUp::freshRequirement()`. The middleware's protected `requirement()` and `strongest()` methods are gone, so overriding them on a subclass of the middleware no longer has any effect. Override `freshRequirement()` or `strongest()` on `StepUp` instead.
- `RequireAssurance` and `RequireFreshVerification` now only have the `$stepUp` property. The `$assurance`, `$keyring`, and `$devices` properties are gone, and the decisions they made are `StepUp::unlessReached()` and `StepUp::unlessFresh()`.
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

Jobs the old version queued still run under the new one. An event that carries an `attempt` (`Authenticated`, `Confirmed`, `FactorChallenged`, `FactorVerified`, `VerificationRefused`) restores, and its attempt looks its user up again. A password's `FactorVerified` still fails, as it did before (see [Events](docs/events.md)). A job for `SessionResumed` or `RememberMeReused` restores without a `handle`, and reading it throws, so drain those first only if a listener for them starts reading `$event->handle` in the same deploy.

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

## From 0.1 to 0.2

There's nothing to change. The new `CredentialStuffing` risk signal is off until you add it to your provider.
