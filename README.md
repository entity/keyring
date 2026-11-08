# Keyring

Factor-driven authentication for Laravel. It's like Fortify, but built to be extended.

- **Many authenticators per user:** two TOTP apps, three security keys, a passkey. One is the default, and the user can "try another way".
- **Factors are drivers:** password, TOTP, WebAuthn (passkeys and security keys), email codes and recovery codes all share one contract. You can add SMS, push or anything else without new routes.
- **Login is a state machine:** one policy decides what's still needed, for example "two different categories, one of them phishing-resistant".
- **Devices and sessions are built in:** new-device events, a session list, "sign out everywhere else", and it works with any session driver.
- **Step-up:** `keyring:aal2` and `keyring.fresh:15m` middleware, where any qualifying factor counts, not just the password.
- **Protected account changes:** email and password can only change through the proper flow (OWASP).
- **Risk signals:** new device, impossible travel, failed MFA after a correct password, and so on, each mapped to an action.

> Work in progress. Not ready for production.

## Requirements

- PHP 8.5+
- Laravel 13+
- Inertia v3 (optional, used for the default page responses)

## Quick start

```php
use Keyring\Facades\Keyring;
use Keyring\Factors\{Password, Totp, RecoveryCodes};
use Keyring\Login\Requirement;

Keyring::factors([
    Password::class,
    Totp::class,
    RecoveryCodes::class,
]);

Keyring::require(Requirement::aal2()->ifEnrolled());
```

```php
class User extends Authenticatable
{
    use \Keyring\Concerns\HasKeyring;
}
```

## Testing

```bash
composer test
```

## License

MIT
