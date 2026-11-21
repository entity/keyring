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

### Queued Listeners

This only matters if you queue listeners for Keyring's events. Some events are now serialised differently, so they don't put registry IDs, password hashes, or secrets on your queue. See [Events](docs/events.md).

Drain the queue before you deploy, and restart your queue workers with the deploy. Jobs queued by the old version don't restore under the new one, and a worker still running the old code can't restore jobs the new one queues either:

- A job for an event that carries an `attempt` (`Authenticated`, `Confirmed`, `FactorChallenged`, `FactorVerified`, `VerificationRefused`) fails with a `TypeError` when the worker unserialises it.
- A job for `SessionResumed` or `RememberMeReused` restores without its `handle`, so reading `$event->handle` throws.

Then prune `failed_jobs` of these events. Rows queued before the upgrade still hold session registry IDs and users' password hashes and remember tokens.

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
