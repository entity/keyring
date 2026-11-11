# Upgrade Guide

Keyring has no tagged release yet, so there's nothing to upgrade from. This guide starts with the first release, and will list anything you need to change when updating from one release to the next.

What counts as a change you'd need to act on is in the README's [What's Stable](README.md#whats-stable). A test (`tests/Feature/PublicApiTest.php`) fails when a config default changes, or a route, middleware alias, facade method, contract, event or email type is renamed or removed, so one can't change without an entry here.

## Before the First Release

Changes made since the first installs from `dev-main`, for anyone already running one:

- **`keyring_sessions` has a `user_type` column.** A session record now names its user's model as well as the ID, so two user models with the same IDs don't share sessions. Add `$table->string('user_type')` and an index on `['user_type', 'user_id']` to your published migration, and empty the table: everyone signs in again. A custom `SessionRegistry` has to store the new `userType` field and match on it in `forUser()`, `revokeAll()` and `revokeDevice()`.
- **`timebox` defaults to `500ms`, up from `250ms`.** It has to be longer than one password hash takes, and bcrypt at 12 rounds is close to 250ms on ordinary hardware. Set it in `config/keyring.php` to keep the old value.
- **An address a change replaced is looked up differently while it's reserved**, so that "ß" is found under either spelling a database takes it for. Reservations made before this, for an address with a doubled "s", aren't found until they lapse (a week at most).
- **Saving the current password as the new one is refused** on `PUT /user/password`, with a validation error on `password`.
- **A mid-session risk step-up signs the session out when `sessions.end_on_lapse` is on**, where it used to carry on with nothing proved.
