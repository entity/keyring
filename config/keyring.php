<?php

use Keyring\Devices\NullLocator;

return [

    /*
    |--------------------------------------------------------------------------
    | Guard & Users
    |--------------------------------------------------------------------------
    |
    | The guard Keyring signs users into, and the user attribute that is used
    | to identify them at login (typically "email"). Login is case-insensitive
    | on this attribute, so store it lowercased.
    |
    */

    'guard' => 'web',

    'username' => 'email',

    /*
    |--------------------------------------------------------------------------
    | Redirects
    |--------------------------------------------------------------------------
    */

    'home' => '/dashboard',

    'login_redirect' => '/login',

    /*
    |--------------------------------------------------------------------------
    | Routes
    |--------------------------------------------------------------------------
    |
    | Keyring registers its routes under these middleware. Set "routes" to
    | false to register them yourself with Keyring::routes().
    |
    */

    'routes' => true,

    'prefix' => '',

    'domain' => null,

    'middleware' => ['web'],

    /*
    |--------------------------------------------------------------------------
    | WebAuthn (Passkeys & Security Keys)
    |--------------------------------------------------------------------------
    |
    | The relying party ID defaults to your APP_URL host, and the allowed
    | origins to your APP_URL. Timeout is in milliseconds.
    |
    */

    'webauthn' => [
        'relying_party' => [
            'id' => env('KEYRING_WEBAUTHN_RP_ID'),
            'name' => env('KEYRING_WEBAUTHN_RP_NAME'),
        ],
        'origins' => [],
        'timeout' => 60_000,
    ],

    /*
    |--------------------------------------------------------------------------
    | Managing Authenticators
    |--------------------------------------------------------------------------
    |
    | Middleware for adding, changing and removing authenticators. Changing
    | how someone signs in needs a recent verification (OWASP).
    |
    */

    'manage_middleware' => ['auth', 'keyring.fresh:15m'],

    /*
    |--------------------------------------------------------------------------
    | Devices
    |--------------------------------------------------------------------------
    |
    | Devices are recognised by a long-lived cookie. "trust_for" enables the
    | "don't ask again on this device" option (set to null to turn it off).
    | A trusted device is only an input to your policy, never a factor.
    |
    */

    'devices' => [
        'cookie' => 'keyring_device',
        'trust_for' => '30d',
        'locator' => NullLocator::class,
    ],

    /*
    |--------------------------------------------------------------------------
    | Sessions
    |--------------------------------------------------------------------------
    |
    | Keyring keeps its own registry of signed-in sessions so they can be
    | listed and revoked on any session driver. Drivers: "database" (the
    | keyring_sessions table) or "cache" (any persistent cache store).
    |
    | Timeouts accept "30m", "12h", "30d"... "idle" null leaves inactivity to
    | Laravel's session lifetime. Levels can override them, e.g.
    | 'levels' => ['aal3' => ['idle' => '15m', 'absolute' => '8h']].
    |
    */

    'sessions' => [
        'driver' => env('KEYRING_SESSION_DRIVER', 'database'),
        'connection' => null,
        'table' => 'keyring_sessions',
        'store' => null,
        'idle' => null,
        'absolute' => '30d',
        'levels' => [],
        'middleware' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Protected Attributes
    |--------------------------------------------------------------------------
    |
    | These user attributes can only change through Keyring's flows (email
    | change with confirmation, password change, password reset). Anything
    | else throws, unless wrapped in Keyring::withoutProtection().
    |
    */

    'protected' => ['email', 'password'],

    'email_changes' => [
        'expire' => '24h',
        'revertable_for' => '7d',
    ],

    /*
    |--------------------------------------------------------------------------
    | Passwords
    |--------------------------------------------------------------------------
    |
    | OWASP: at least 8 characters with MFA, 15 without, allow at least 64,
    | any characters, no composition rules, and block breached passwords.
    | Bcrypt silently ignores anything past 72 bytes, so with bcrypt longer
    | passwords are rejected rather than truncated.
    |
    */

    'passwords' => [
        'min_with_mfa' => 8,
        'min_without_mfa' => 15,
        'max' => 128,
        'uncompromised' => true,
        'broker' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Risk
    |--------------------------------------------------------------------------
    |
    | Signal scores add up (0-100) into a level. Configure signals and what to
    | do at each level with Keyring::risk([...])->respond(fn ...). By default:
    | medium asks for another factor, high also notifies, critical refuses the
    | sign in and signs out every session.
    |
    */

    'risk' => [
        'levels' => ['medium' => 30, 'high' => 60, 'critical' => 90],
        'recent_change' => '7d',
        'store' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Log
    |--------------------------------------------------------------------------
    |
    | Sign ins, failures, lockouts, changes and automatic actions are logged to
    | keyring_events. Prune with `php artisan model:prune`.
    |
    */

    'events' => [
        'enabled' => true,
        'keep_for' => '180d',
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Emails
    |--------------------------------------------------------------------------
    |
    | Which security emails Keyring sends. Off by default: your app may want
    | to send its own. Call Keyring::notify() to turn them all on, or list
    | types: new_device, password_changed, authenticator_added,
    | authenticator_removed, second_factor_failed, recovery_code_used,
    | suspicious_activity, clone_suspected.
    |
    */

    'notifications' => [],

    /*
    |--------------------------------------------------------------------------
    | Pending Logins
    |--------------------------------------------------------------------------
    |
    | How long a half-finished login (password accepted, second factor still
    | needed) stays valid before the user has to start over.
    |
    */

    'pending_login_ttl' => 600,

    /*
    |--------------------------------------------------------------------------
    | Timebox
    |--------------------------------------------------------------------------
    |
    | Every factor verification runs for at least this long (microseconds),
    | so response timing doesn't reveal whether an account exists.
    |
    */

    'timebox' => 250_000,

    /*
    |--------------------------------------------------------------------------
    | Rate Limits
    |--------------------------------------------------------------------------
    |
    | Default attempts per minute, per account and per IP address. Factors may
    | declare their own limits.
    |
    */

    'limits' => [
        'per_account' => 5,
        'per_ip' => 20,
    ],

];
