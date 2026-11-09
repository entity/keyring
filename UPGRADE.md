# Upgrade Guide

## Upgrading From a Pre-Release Install

Keyring has no tagged release yet, so there's nothing to upgrade between. This section is for apps that installed `dev-main` while it was being built. Names changed without aliases, because nothing had shipped. Once the first release is tagged, this guide starts again from there.

### Facade Methods

| Was | Now |
|---|---|
| `Keyring::risk([...])` | `Keyring::risk()->signals([...])` |
| `Keyring::notify([...])` | `Keyring::sendSecurityNotices([...])` |
| `Keyring::notifies($type)` | `Keyring::sendsSecurityNotice($type)` |
| `Keyring::changing()`, `Keyring::guardProtectedAttributes()` | Removed. They were internal. Use [`Keyring::withoutProtection()`](docs/protected-changes.md#bypassing-protection) to change a protected attribute. |

### Config Options

| Was | Now |
|---|---|
| `notifications` | `security_notices` |
| `events` | `security_log` |
| `pending_login_ttl` | `pending_logins.keep_for` |
| `email_changes.expire` | `email_changes.confirmable_for` |
| `manage_middleware` | `changes_middleware` |
| `timebox` in microseconds (`250_000`) | A duration (`'250ms'`) |
| `webauthn.timeout` in milliseconds (`60_000`) | A duration (`'60s'`) |

A bare number for `timebox` or `webauthn.timeout` now throws, since guessing the unit could be a thousand times out. An old key is ignored without an error, so check your published `config/keyring.php` for each one.

### Migrations

The create migrations were edited in place. A database migrated from an earlier copy needs a migration of your own for whichever of these it's missing:

| Table | Change |
|---|---|
| `keyring_pending_changes` | A nullable `signed_in_at` timestamp. |
| `keyring_pending_changes` | A nullable, indexed `previous_value_hash` string of 64 characters. |
| `keyring_authenticators` | `credential_id` widened to 512 characters. |
| `keyring_devices` | An index on `token_hash`. |
| `keyring_sessions` | An index on `expires_at`. |
| `keyring_events` | An index on `authenticatable_type`, `authenticatable_id`, `type` and `created_at`, named `keyring_events_owner_type_index`. |

The [example app](https://github.com/entity/keyring-example/tree/main/database/migrations) has migrations that do this.

### Published Actions

The published `UpdateUserPassword` action now checks the current password with `Keyring\Rules\CurrentPassword` instead of Laravel's `current_password` rule. An action still on Laravel's rule keeps working. See [Changing the Password](docs/protected-changes.md#changing-the-password).

### Behaviour

- **A user model needs `HasKeyring`.** Signing in a model without it throws `Keyring\Exceptions\MissingTrait`.
- **Trusting a device takes a second factor.** A password-only sign in with `trust` no longer marks the device trusted, and trust ends when an authenticator is removed, the email address changes, the password changes or a risk lock is placed. See [Trusted Devices](docs/devices-and-sessions.md#trusted-devices).
- **The device cookie changes** on every sign in that proves two categories.
- **The per-IP rate limit locks for 15 minutes at most**, and a browser the account has used before isn't held up by it. See [Rate Limiting](docs/security.md#rate-limiting).
- **Each account can be sent three codes per factor every 10 minutes.**
- **`SecurityLog::record()` returns `null`** when the log is off or the write failed, and a log or locator failure no longer stops a sign in.
