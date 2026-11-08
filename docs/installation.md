# Installation

- [Requirements](#requirements)
- [Installing Keyring](#installing-keyring)
- [What Gets Published](#what-gets-published)
- [Preparing Your User Model](#preparing-your-user-model)
- [Frontend](#frontend)
- [Routes Keyring Registers](#routes-keyring-registers)
- [After Installing](#after-installing)

## Requirements

- PHP 8.5 or later
- Laravel 13 or later
- Inertia v3 (optional). Without Inertia, Keyring renders Blade views instead (see [Pages](sign-in-flow.md#pages)).
- The `sodium` PHP extension, if you want passkeys and security keys that sign with Ed25519. Without it, Keyring only offers ES256 and RS256 keys.

## Installing Keyring

Install the package with Composer, then run the install command:

```bash
composer require entity/keyring

php artisan keyring:install
php artisan migrate
```

Pass `--force` to overwrite files that already exist; without it, existing files are skipped. It's safe to run again: the migrations are only published once, so they're never added twice under new timestamps. Running it again on an older install adds any new actions, but leaves your provider alone, so register them there yourself. Until you do, the routes that need them fail with an exception that says which `Keyring::*Using()` call is missing.

If you're moving from Fortify, read [Upgrading From Fortify](upgrading-from-fortify.md) before migrating.

## What Gets Published

`keyring:install` publishes:

| File | What it is |
|---|---|
| `config/keyring.php` | The configuration file. |
| `database/migrations/*_create_keyring_*_table.php` | Five tables: `keyring_authenticators`, `keyring_devices`, `keyring_sessions`, `keyring_pending_changes` and `keyring_events`. |
| `app/Providers/KeyringServiceProvider.php` | Where you register factors and the policy. It's added to `bootstrap/providers.php` for you. |
| `app/Actions/Keyring/*.php` | Your code for registration (`CreateNewUser`), password resets (`ResetUserPassword`), password changes (`UpdateUserPassword`), email change requests (`ValidateEmailChange`), and the password rules they share (`PasswordValidationRules`). Keyring does the security work around them. |

You can publish the same files on their own with the `keyring-config`, `keyring-migrations` and `keyring-lang` tags:

```bash
php artisan vendor:publish --tag=keyring-lang
```

The migrations use `morphs()` to link rows to users. If your users have UUID or ULID keys, set Laravel's default morph key type (for example with `Schema::morphUsingUlids()`) before running them, or edit the published migrations.

## Preparing Your User Model

Add the `HasKeyring` trait to your user model:

```php
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring;

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
}
```

The trait does three things:

- It adds `$user->keyring`, `$user->authenticators()` and `$user->devices()`.
- It stops the `email` and `password` attributes from changing outside Keyring's own flows. See [Protected Changes](protected-changes.md).
- When the user is deleted, it revokes their sessions and deletes their authenticators, devices and pending changes. With soft deletes, this only happens on a force delete.

The published `CreateNewUser` action passes the plain password to `User::create()`, so it relies on the `hashed` cast shown above. The password actions hash it themselves.

Implementing `MustVerifyEmail` is recommended. Users who implement it must verify their address before they can add a sign-in method. See [Managing Authenticators](authenticators.md#email-verification).

Keyring looks users up by the `email` attribute by default (see `username` in [Configuration](configuration.md#guard-and-users)). Lookups trim and lowercase the input, so store addresses the same way. `Keyring::normalizeUsername()` does exactly that, and the published `CreateNewUser` action uses it.

## Frontend

Your pages can use `@entity/keyring`, Keyring's browser package, for WebAuthn and the challenge page (see [Frontend](frontend.md)):

```bash
npm install @entity/keyring
```

See [Frontend](frontend.md) for what the package provides.

## Routes Keyring Registers

Keyring registers its routes under the `web` middleware group by default, and every signed-in route checks Keyring's guard (`auth:{guard}`). Some use the same names as Laravel's conventions and Fortify (`login`, `logout`, `register`, `password.request`, `password.reset`, `verification.notice` and so on), so remove any routes of your own with those names. The full list is in [The Sign In Flow](sign-in-flow.md#routes), [Step-Up](step-up.md), [Managing Authenticators](authenticators.md#routes), [Devices & Sessions](devices-and-sessions.md#routes) and [Protected Changes](protected-changes.md#routes).

To change the prefix, domain or middleware, or to turn routes off, see [Configuration](configuration.md#routes).

## After Installing

- Set `APP_URL` to the address users actually visit. Keyring builds emailed links from it, and passkeys and security keys only work on that origin unless you configure others. See [Passkeys & Security Keys](passkeys.md#relying-party-and-origins).
- Open `app/Providers/KeyringServiceProvider.php` and choose your [factors](factors.md) and [policy](policies.md).
- Schedule `keyring:prune`, which clears out old devices, finished email changes, old security log entries and ended sessions:

  ```php
  // routes/console.php
  use Illuminate\Support\Facades\Schedule;

  Schedule::command('keyring:prune')->daily();
  ```

  See [Pruning](devices-and-sessions.md#pruning).
