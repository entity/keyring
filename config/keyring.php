<?php

use Keyring\Devices\NullLocator;
use Keyring\Features;

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
    | Features
    |--------------------------------------------------------------------------
    |
    | Signing in and out, challenges and step-up are always on. Add the rest
    | as your app needs them. Each one brings its routes, and anything else
    | it needs, only once it's here.
    |
    */

    'features' => [
        Features::registration(),
        Features::resetPasswords(),
        // Features::emailVerification(),
        // Features::updatePasswords(),
        // Features::manageAuthenticators(),
        // Features::devices(),
        // Features::emailChanges(),
        // Features::securityLog(),
    ],

    /*
    |--------------------------------------------------------------------------
    | Redirects
    |--------------------------------------------------------------------------
    */

    'home' => '/dashboard',

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
    | Extra middleware for adding, changing and removing authenticators (on
    | top of being signed in to Keyring's guard). Changing how someone signs
    | in needs a recent verification (OWASP).
    |
    */

    'manage_middleware' => ['keyring.fresh:15m'],

    /*
    |--------------------------------------------------------------------------
    | Enrollment Page
    |--------------------------------------------------------------------------
    |
    | Where the keyring.enrolled middleware sends users who still need to add
    | a second factor: your page for setting one up. Null answers 403.
    |
    */

    'enrollment_url' => null,

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
    | Timeouts accept "30m", "12h", "30d"... "idle" and "absolute" end the
    | session ("idle" null leaves inactivity to Laravel's session lifetime).
    | "levels" are how long each assurance level keeps counting: past them the
    | user stays signed in, and routes that need the level ask them to verify
    | again. The defaults are NIST SP 800-63B's reauthentication limits.
    |
    */

    'sessions' => [
        'driver' => env('KEYRING_SESSION_DRIVER', 'database'),
        'connection' => null,
        'table' => 'keyring_sessions',
        'store' => null,
        'idle' => null,
        'absolute' => '30d',
        'levels' => [
            'aal2' => ['idle' => '1h', 'absolute' => '24h'],
            'aal3' => ['idle' => '15m', 'absolute' => '12h'],
        ],
        'middleware' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Protected Attributes
    |--------------------------------------------------------------------------
    |
    | Attributes that may only change through Keyring's flows: anything else
    | throws, unless wrapped in Keyring::withoutProtection(). The password is
    | added with Features::updatePasswords(), the email with
    | Features::emailChanges(). List any others here.
    |
    */

    'protected' => [],

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
    | "uncompromised" checks new passwords against Have I Been Pwned over the
    | network. Null runs it in production only, so local and test runs make
    | no network calls.
    |
    */

    'passwords' => [
        'min_with_mfa' => 8,
        'min_without_mfa' => 15,
        'max' => 128,
        'uncompromised' => null,
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
    | With Features::securityLog(), sign ins, failures, lockouts, changes and
    | automatic actions are logged to keyring_events. Prune with
    | `php artisan model:prune`.
    |
    */

    'events' => [
        'keep_for' => '180d',

        // Shown once as "was this you?" at the next sign in (keyring.alerts).
        'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Emails
    |--------------------------------------------------------------------------
    |
    | Which security notices Keyring sends to the user. NIST SP 800-63B asks
    | for password_changed, authenticator_added, authenticator_removed and
    | recovery_code_used. The others: new_device, second_factor_failed,
    | suspicious_activity, clone_suspected. Keyring::notify() with no types
    | sends them all.
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

    'pending_login_ttl' => '10m',

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
    | Default attempts per minute, per account and per IP address, and the
    | failures in a row an account's factor allows however slowly they come
    | (NIST SP 800-63B caps them at 100; null for no cap). At that cap the
    | factor is refused until a password reset. Factors may declare their own
    | limits.
    |
    */

    'limits' => [
        'per_account' => 5,
        'per_ip' => 20,
        'consecutive' => 100,
    ],

];
