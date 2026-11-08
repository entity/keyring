# Keyring

Factor-driven authentication for Laravel. It feels like Fortify, but it's built to be extended.

Fortify keeps 2FA in three columns on `users`. That gives one TOTP per user, and everything else gets bolted on. Keyring treats every way of signing in as a **factor** behind one contract. A user holds as many **authenticators** as they like, and one **policy** decides what they must prove.

- **Many authenticators per user:** two authenticator apps, three security keys, a passkey. One is the default, and the user can "try another way".
- **Factors are drivers:** password, TOTP, passkeys, security keys, email codes and recovery codes all share one contract. You can add SMS, push or anything else without new routes, controllers or tables.
- **Passkeys and security keys work as either factor:** one WebAuthn driver with two profiles. Inherence only counts when the key actually verified the user.
- **Devices and sessions are built in:** new-device events, "this wasn't me" links, a sessions list, and "sign out everywhere else". It works with **any session driver** (database, cache, file, cookie).
- **Step-up:** `keyring:aal2` and `keyring.fresh:15m` middleware. A passkey or code counts, not just the password, and users with a second factor must use it.
- **Protected account changes:** `email` and `password` can only change through Keyring's flows (OWASP). Email changes are confirmed from both addresses and can be reverted.
- **Risk signals:** new device, new country, impossible travel, a session cookie showing up in another browser, repeated failures. Each level maps to an action.
- **A security log and opt-in security emails.**
- **Headless:** Inertia pages by default, swappable responses, published actions. `keyring:install --inertia=vue|react` gives you working pages.

> Work in progress: not tagged or production-tested yet.

## Requirements

- PHP 8.5+
- Laravel 13+
- Inertia v3 (optional; without it, Keyring renders Blade views named `auth.*` that you provide)

## Installation

```bash
composer require entity/keyring
php artisan keyring:install --inertia=vue   # or react, or leave it off for headless
php artisan migrate
```

Add the trait to your user model:

```php
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable
{
    use HasKeyring;
}
```

Then choose your factors and policy in the published `app/Providers/KeyringServiceProvider.php`:

```php
Keyring::factors([
    Password::class,
    WebAuthn::passkeys(),
    WebAuthn::securityKeys(),
    Totp::class,
    EmailCode::class,
    RecoveryCodes::class,
]);

Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
```

Coming from Fortify? `php artisan keyring:import fortify` copies `two_factor_*` columns and the `laravel/passkeys` table into Keyring. Users keep their authenticator apps, recovery codes and passkeys.

For the frontend helpers:

```bash
npm install @entity/keyring
```

## Documentation

- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Upgrading From Fortify](docs/upgrading-from-fortify.md)
- [Factors](docs/factors.md)
- [Policies](docs/policies.md)
- [The Sign In Flow](docs/sign-in-flow.md)
- [Step-Up](docs/step-up.md)
- [Passkeys & Security Keys](docs/passkeys.md)
- [Managing Authenticators](docs/authenticators.md)
- [Devices & Sessions](docs/devices-and-sessions.md)
- [Protected Changes](docs/protected-changes.md)
- [Risk](docs/risk.md)
- [Security Log & Emails](docs/security-log-and-emails.md)
- [Frontend](docs/frontend.md)
- [Testing](docs/testing.md)
- [Security](docs/security.md)

## Contributing

```bash
composer test      # tests
composer lint      # code style
composer analyse   # static analysis
composer refactor  # apply Rector's rules
composer check     # everything CI runs: Rector (dry run), Pint, PHPStan and Pest
```

Run `composer check` before opening a pull request.

## License

MIT
