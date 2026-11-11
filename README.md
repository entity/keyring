# Keyring

Factor-driven authentication for Laravel. It feels like Fortify, but it's built to be extended.

It starts as small as Fortify: password sign-in, sign-out, and your own actions and pages. Then you add what your app needs, one feature or sign-in method at a time.

Fortify keeps 2FA in three columns on `users`. That gives one TOTP per user, and everything else gets bolted on. Keyring treats every way of signing in as a **factor** behind one contract. A user holds as many **authenticators** as they like, and one **policy** decides what they must prove.

- **Many authenticators per user:** two authenticator apps, three security keys, a passkey. One is the default, and the user can "try another way".
- **Factors are drivers:** password, TOTP, passkeys, security keys, email codes and recovery codes all share one contract. You can add SMS, push or anything else without new routes, controllers or tables.
- **Passkeys and security keys work as either factor:** one WebAuthn driver with two profiles. Inherence only counts when the key actually verified the user.
- **Devices and sessions:** new-device events, "this wasn't me" links, a sessions list, and "sign out everywhere else". It works with **any session driver** (database, cache, file, cookie).
- **Step-up:** `keyring:aal2` and `keyring.fresh:15m` middleware. A passkey or code counts, not just the password, and users with a second factor must use it.
- **Protected account changes:** once Keyring handles them, `email` and `password` can only change through its flows. Email changes are confirmed from both addresses and can be reverted.
- **Risk signals:** new device, new country, impossible travel, a session cookie showing up in another browser, repeated failures, a password found in a breach. Each level maps to an action, and a new app starts with the signals its features can feed.
- **A security log and security emails.** The emails are sent from the start, and each can be swapped for your own notification, restyled or turned off.
- **Built on OWASP ASVS 5.0.0 and NIST SP 800-63B-4:** [one page](docs/owasp-asvs.md) goes through both, requirement by requirement. Each is met, partly met, waiting on something you turn on, a deliberate deviation or your app's job, and the page says which and why.
- **Headless:** like Fortify, Keyring renders your pages with props and answers JSON, with swappable responses and published actions. A browser package handles WebAuthn and the challenge page for Vue and React.

Every feature and sign-in method beyond the password is opt-in. See [Adding Features](docs/quick-start.md#adding-features).

> Work in progress: not tagged or production-tested yet.

## Requirements

- PHP 8.5+
- Laravel 13.31+
- Inertia v3 (optional; without it, Keyring renders Blade views named `auth.*` that you provide)

## Installation

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

`keyring:install` asks which sign-in methods and features you want, and sets up what they need. Then add the trait to your user model. Users who register themselves verify their address before they can sign in, so implement `MustVerifyEmail` too:

```php
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring;
}
```

The [Quick Start](docs/quick-start.md) covers the pages to build and how to add features later.

Coming from Fortify? `php artisan keyring:import fortify` copies `two_factor_*` columns and the `laravel/passkeys` table into Keyring. Users keep their authenticator apps, recovery codes and passkeys.

For the frontend helpers:

```bash
npm install @entity/keyring
```

> It isn't on npm yet either. Until it is, build it from the Composer package: see [Frontend](docs/frontend.md#introduction).

## Documentation

- [Quick Start](docs/quick-start.md)
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
- [Events](docs/events.md)
- [Frontend](docs/frontend.md)
- [Example app](https://github.com/entity/keyring-example): every page, in React with the Laravel starter kit
- [Extending Keyring](docs/extending.md)
- [Recipes](docs/recipes.md)
- [Testing](docs/testing.md)
- [Security](docs/security.md)
- [OWASP ASVS and NIST SP 800-63B](docs/owasp-asvs.md)

The [changelog](CHANGELOG.md) lists what each release changes, and the [upgrade guide](UPGRADE.md) covers anything you need to do when updating.

## Security Vulnerabilities

Please don't open a public issue for a security problem. See the [security policy](SECURITY.md) for how to report one.

## Contributing

```bash
composer test      # tests
composer lint      # code style
composer analyse   # static analysis
composer refactor  # apply Rector's rules
composer check     # everything CI runs: Rector (dry run), Pint, PHPStan and Pest
```

Run `composer check` before opening a pull request.

The race tests run operations in separate processes against a real database, so they need PostgreSQL or MySQL and run as their own suite (CI runs them on both):

```bash
DB_CONNECTION=pgsql DB_DATABASE=keyring_test vendor/bin/pest --testsuite=Concurrency
```

## License

MIT
