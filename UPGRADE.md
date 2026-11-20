# Upgrade Guide

This guide lists anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

## From 0.2 to 0.3

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

## From 0.1 to 0.2

There's nothing to change. The new `CredentialStuffing` risk signal is off until you add it to your provider.
