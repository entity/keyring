<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="art/logo-dark.svg">
    <img src="art/logo-light.svg" alt="Keyring" width="320">
  </picture>
</p>

<p align="center">Factor-driven authentication for Laravel. Start with a password, then add passkeys, second factors, devices and step-up.</p>

<p align="center">
  <a href="https://packagist.org/packages/keyring/keyring"><img src="https://img.shields.io/packagist/v/keyring/keyring" alt="Latest version"></a>
  <a href="https://www.npmjs.com/package/@keyringjs/keyring"><img src="https://img.shields.io/npm/v/@keyringjs/keyring?label=npm" alt="npm version"></a>
  <a href="LICENSE.md"><img src="https://img.shields.io/packagist/l/keyring/keyring" alt="License"></a>
</p>

Keyring handles sign-in, registration, password resets, email verification and the account security around them. It's headless: your app owns the pages, and Keyring handles the requests behind them.

Every way of signing in is a **factor** behind one contract. A user can hold as many **authenticators** as they like, and a **policy** decides what they must prove.

> [!NOTE]
> Keyring is new and not production-tested yet. Until 1.0, a minor release may change the public API. See [What's stable](#whats-stable).

## Features

- **Many authenticators per user:** authenticator apps, passkeys, security keys, email codes and recovery codes, with "try another way". [Factors](docs/factors.md)
- **Your own factors:** add SMS, push or anything else without new routes, controllers or tables. [Extending](docs/extending.md)
- **Devices and sessions:** new-device emails, a sessions list and "sign out everywhere else", on any session driver. [Devices & Sessions](docs/devices-and-sessions.md)
- **Step-up:** `keyring:aal2` and `keyring.fresh:15m` middleware that accept a passkey or code, not just the password. [Step-Up](docs/step-up.md)
- **Protected changes:** email changes are confirmed from both addresses and can be reverted. [Protected Changes](docs/protected-changes.md)
- **Risk signals:** new devices, new countries, impossible travel, session cookies reused in another browser and breached passwords. [Risk](docs/risk.md)
- **Security log and emails:** sent from day one, and each can be swapped, restyled or turned off. [Security Log & Emails](docs/security-log-and-emails.md)
- **Built on OWASP ASVS 5.0.0 and NIST SP 800-63B-4:** every requirement mapped on [one page](docs/owasp-asvs.md).
- **Headless:** your pages, Inertia or Blade, plus a browser package for WebAuthn in Vue and React. [Frontend](docs/frontend.md)

## Installation

Keyring needs PHP 8.5+ and Laravel 13.31+. Inertia v3 is optional; without it, Keyring renders Blade views you provide.

```bash
composer require keyring/keyring
php artisan keyring:install
php artisan migrate
```

`keyring:install` asks which sign-in methods and features you want and sets them up. Then add the trait to your user model:

```php
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Keyring\Concerns\HasKeyring;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasKeyring;
}
```

For passkeys and the challenge page in the browser:

```bash
npm install @keyringjs/keyring
```

The [Quick Start](docs/quick-start.md) walks through the pages to build. Already using Fortify? See [Upgrading From Fortify](docs/upgrading-from-fortify.md).

## Start small, add what you need

A new install covers password sign-in, registration, password resets, email verification and password changes. Rate limits, password rules, session timeouts, the security log and security emails are on from the start.

Everything else is already in your app, commented out:

| To add | Uncomment |
|---|---|
| Authenticator apps, passkeys, security keys or email codes | Its line in `Keyring::factors([...])` and `Features::manageAuthenticators()` |
| A second factor for everyone | The `keyring.enrolled` line in your provider |
| Trusted devices, a sessions list, new-device emails | `Features::devices()` |
| Confirmed, undoable email changes | `Features::emailChanges()` |
| More risk signals | Their lines in `Keyring::risk()->signals([...])` |

See [Adding Features](docs/quick-start.md#adding-features) for the pages each one needs.

## Documentation

- **Getting started:** [Quick Start](docs/quick-start.md) · [Installation](docs/installation.md) · [Configuration](docs/configuration.md) · [Upgrading From Fortify](docs/upgrading-from-fortify.md)
- **Signing in:** [Factors](docs/factors.md) · [Policies](docs/policies.md) · [The Sign In Flow](docs/sign-in-flow.md) · [Step-Up](docs/step-up.md) · [Passkeys & Security Keys](docs/passkeys.md)
- **Account security:** [Authenticators](docs/authenticators.md) · [Devices & Sessions](docs/devices-and-sessions.md) · [Protected Changes](docs/protected-changes.md) · [Risk](docs/risk.md) · [Security Log & Emails](docs/security-log-and-emails.md) · [Events](docs/events.md)
- **Building your app:** [Frontend](docs/frontend.md) · [Extending](docs/extending.md) · [Recipes](docs/recipes.md) · [Testing](docs/testing.md) · [Example app](https://github.com/entity/keyring-example)
- **Security:** [Security](docs/security.md) · [OWASP ASVS and NIST SP 800-63B](docs/owasp-asvs.md)

The [changelog](CHANGELOG.md) lists what each release changes, and the [upgrade guide](UPGRADE.md) covers what to do when updating.

## What's stable

Everything the docs describe is public API: config options, routes, middleware, the facade, builders, contracts, events, emails, log entry types, commands, testing helpers and the browser package's exports. Changes to any of these are called out in the [upgrade guide](UPGRADE.md), and before 1.0 a minor release may make one.

The rest of `src/` (controllers, pipeline internals, `Keyring\Support`) can change in any release. If you need to extend one of those, [Extending Keyring](docs/extending.md) probably has a supported way, and an issue is welcome when it doesn't.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please report security problems privately, as the [security policy](SECURITY.md) describes, not in a public issue.

## License

MIT. See [LICENSE.md](LICENSE.md).
