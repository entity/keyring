# Installation

The [Quick Start](quick-start.md) is the short version. This page has the details.

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

> Keyring has no tagged release yet. Until it does, install it from GitHub:
>
> ```bash
> composer config repositories.keyring vcs https://github.com/entity/keyring
> composer require entity/keyring:dev-main
> ```

The command asks which sign-in methods you want besides the password, which [features](quick-start.md#adding-features) to turn on, and whether to email users when their password or sign-in methods change. Recovery codes come with any second sign-in method. Picking registration with a sign-in method also turns on email verification, since users who register themselves must prove their address before adding one. Without prompts (`--no-interaction`, or in CI) you get the password, registration and password resets, and the security emails whenever you pick a second sign-in method. You can also answer with options:

```bash
php artisan keyring:install --factor=totp --factor=passkeys --feature=registration --feature=manage-authenticators --emails
```

`--factor` takes `totp`, `passkeys`, `security-keys` or `email-codes`. `--feature` takes `registration`, `reset-passwords`, `email-verification`, `update-passwords`, `manage-authenticators`, `devices`, `email-changes` or `security-log`, and replaces the defaults (`registration` and `reset-passwords`), so list those too if you want them. An unknown value stops the command before it writes anything, and an unknown feature in `config/keyring.php` stops the app booting, rather than leaving that feature off. `--no-emails` leaves the security emails out.

Pass `--force` to overwrite files that already exist; without it, existing files are skipped, and with `config/keyring.php` already there it doesn't ask which features to turn on. It's safe to run again: the migrations are only published once, so they're never added twice under new timestamps. Running it again on an older install adds any new actions, but leaves your provider alone, so register them there yourself. Until you do, the routes that need them fail with an exception that says which `Keyring::*Using()` call is missing.

If you're moving from Fortify, read [Upgrading From Fortify](upgrading-from-fortify.md) before migrating.

## What Gets Published

`keyring:install` publishes:

| File | What it is |
|---|---|
| `config/keyring.php` | A short config: the guard, username, home, your features, security emails and enrollment page. Every other option keeps Keyring's default; copy any from [Configuration](configuration.md) to change it. |
| `database/migrations/*_create_keyring_*_table.php` | Five tables: `keyring_authenticators`, `keyring_devices`, `keyring_sessions`, `keyring_pending_changes` and `keyring_events`. They're all created, so turning a feature on later needs no new migration. Tables for features you don't use stay empty. |
| `app/Providers/KeyringServiceProvider.php` | Where you register sign-in methods, the policy and your actions. It lists the sign-in methods you picked, and it's added to `bootstrap/providers.php` for you. |
| `app/Actions/Keyring/*.php` | Your code for the features that need it, all published and registered so a feature works as soon as you turn it on: registration (`CreateNewUser`), password resets (`ResetUserPassword`), password changes (`UpdateUserPassword`), email change requests (`ValidateEmailChange`), and the password rules they share (`PasswordValidationRules`). Keyring does the security work around them. |

You can publish files on their own with the `keyring-config`, `keyring-migrations` and `keyring-lang` tags. `keyring-config` publishes the full config file, with every option and its default:

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
- Once Keyring handles changing them (`Features::updatePasswords()` and `Features::emailChanges()`), it stops the `password` and `email` attributes from changing outside Keyring's own flows. See [Protected Changes](protected-changes.md).
- When the user is deleted, it revokes their sessions and ends their reset links, and deletes their authenticators, devices and pending changes. With soft deletes, the sessions and reset links go straight away and the rest waits for a force delete, so a restored user keeps their sign-in methods.

The published `CreateNewUser` action passes the plain password to `User::create()`, so it relies on the `hashed` cast shown above. The password actions hash it themselves.

Implement `MustVerifyEmail` together with `Features::emailVerification()`; one doesn't work without the other. With the interface but not the feature, registering throws an exception saying so, before anything is saved. Users who implement it must verify their address before they can add a sign-in method. With registration and sign-in methods both on, that's required: see [Managing Authenticators](authenticators.md#email-verification).

Keyring looks users up by the `email` attribute by default (see `username` in [Configuration](configuration.md#guard-and-users)). Lookups trim and lowercase the input, so store addresses the same way. `Keyring::normalizeUsername()` does exactly that, and the published `CreateNewUser` action uses it. To normalise differently, see [Finding the User](sign-in-flow.md#finding-the-user).

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
- Build your [pages](quick-start.md#your-pages).
- Run a queue worker if your queue isn't `sync`. [Security emails](security-log-and-emails.md#security-emails) are queued, so they wait for one, while sign-in codes go out straight away.
- Add [features](quick-start.md#adding-features) and [sign-in methods](quick-start.md#adding-sign-in-methods) as you need them.
- Schedule `keyring:prune`, which clears out old devices, finished email changes, old security log entries and ended sessions:

  ```php
  // routes/console.php
  use Illuminate\Support\Facades\Schedule;

  Schedule::command('keyring:prune')->daily();
  ```

  See [Pruning](devices-and-sessions.md#pruning).
