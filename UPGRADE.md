# Upgrade Guide

This guide lists anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

## Unreleased

This only matters if you queue listeners for Keyring's events. Some events are now serialised differently, so they don't put registry IDs, password hashes, or secrets on your queue. See [Events](docs/events.md).

Drain the queue before you deploy. Jobs queued by the old version don't restore under the new one:

- A job for an event that carries an `attempt` (`Authenticated`, `Confirmed`, `FactorChallenged`, `FactorVerified`, `VerificationRefused`) fails with a `TypeError` when the worker unserialises it.
- A job for `SessionResumed` or `RememberMeReused` restores without its `handle`, so reading `$event->handle` throws.

Then prune `failed_jobs` of these events. Rows queued before the upgrade still hold session registry IDs and users' password hashes and remember tokens.

A queued listener for `SessionResumed` or `RememberMeReused` now gets the session with a blank `id` and a null `replacedBy`. Code that used the ID does nothing now. For example, `Sessions::revoke($user, $event->session)` won't find the session. Use the event's `handle` instead:

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
