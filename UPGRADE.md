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

A [driver of your own](docs/devices-and-sessions.md#writing-a-driver) should store `origin` with the rest of a record and return it from `find` and `forUser`. If you store `$session->toArray()` and read it back with `RegisteredSession::fromArray()`, it already does. A driver that drops it still works, but its sessions get a new handle every time they move. The [conformance suite](docs/testing.md#the-conformance-suite) has a check for this.

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

## From 0.1 to 0.2

There's nothing to change. The new `CredentialStuffing` risk signal is off until you add it to your provider.
