# Upgrade Guide

Keyring has no tagged release yet, so there's nothing to upgrade from. This guide starts with the first release, and will list anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

## Before the First Release

Changes made since the first installs from `dev-main`, for anyone already running one:

- **`keyring_sessions` has a `user_type` column.** A session record now says which table its user's ID is one of (the connection and table, as `RegisteredSession::typeOf($user)` gives it), so two user models with the same IDs don't share sessions. Add `$table->string('user_type')` and an index on `['user_type', 'user_id']` to your published migration, and empty the table: everyone signs in again. With the `cache` driver there's nothing to change: a record from before has no type, isn't found, and its browser signs in again. A custom `SessionRegistry` has to store the new `userType` field and match on it in `forUser()`, `revokeAll()` and `revokeDevice()`.
- **`timebox` defaults to `500ms`, up from `250ms`.** It has to be longer than one password hash takes, and bcrypt at 12 rounds is close to 250ms on ordinary hardware. Set it in `config/keyring.php` to keep the old value.
- **An address a change replaced is looked up differently while it's reserved**, so that "ß" is found under either spelling a database takes it for. Reservations made before this, for an address with a doubled "s", aren't found until they lapse (a week at most).
- **Rate limits, locks and risk locks are kept under new keys.** Ones in place when this is deployed are left behind: an account locked then is unlocked early, once.
- **What a form or Inertia response flashes for the page is encrypted.** Read it with `Keyring::result()` (or `Keyring::result('recoveryCodes')` for one key) instead of `session('keyring.result')`, which now holds ciphertext. In an Inertia middleware, share `'keyringResult' => fn () => Keyring::result()`. JSON responses are unchanged.
- **Saving the current password as the new one is refused** on `PUT /user/password`, with a validation error on `password`.
- **A mid-session risk step-up signs the session out when `sessions.end_on_lapse` is on**, where it used to carry on with nothing proved.
- **`webauthn.relying_party.name` is gone.** WebAuthn deprecates the relying party name and most browsers don't show it, so the options now carry the relying party ID in its place, as Laravel's passkeys package does. Remove the key and `KEYRING_WEBAUTHN_RP_NAME` from your config, and any call to or override of `Ceremonies::relyingPartyName()`, which is gone too. Keys registered before keep working.
