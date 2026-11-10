<?php

use Keyring\Devices\NullLocator;
use Keyring\Features;
use Keyring\Http\Middleware\PreventCaching;

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
    | "email" is the attribute holding their address, for password resets,
    | email changes and email codes. It's only different from "username" when
    | users sign in with something else, like a handle.
    |
    */

    'guard' => 'web',

    'username' => 'email',

    'email' => 'email',

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
    | false to register them yourself with Keyring::routes(). PreventCaching
    | keeps auth pages out of caches and their URLs out of Referer headers.
    |
    */

    'routes' => true,

    'prefix' => '',

    'domain' => null,

    'middleware' => ['web', PreventCaching::class],

    /*
    |--------------------------------------------------------------------------
    | WebAuthn (Passkeys & Security Keys)
    |--------------------------------------------------------------------------
    |
    | The relying party ID defaults to your APP_URL host, and the allowed
    | origins to your APP_URL. The timeout is how long the browser waits.
    |
    | "attestation_roots" are the root certificates a key's attestation has
    | to chain to, for a factor set up with requireAttestation(): PEM
    | certificates, or paths to PEM files.
    |
    */

    'webauthn' => [
        'relying_party' => [
            'id' => env('KEYRING_WEBAUTHN_RP_ID'),
            'name' => env('KEYRING_WEBAUTHN_RP_NAME'),
        ],
        'origins' => [],
        'timeout' => '60s',
        'attestation_roots' => [],
    ],

    /*
    |--------------------------------------------------------------------------
    | Account Changes
    |--------------------------------------------------------------------------
    |
    | Extra middleware for the routes that change how someone signs in: their
    | authenticators, devices, password and email address (on top of being
    | signed in to Keyring's guard). By default they need a recent
    | verification.
    |
    */

    'changes_middleware' => ['keyring.fresh:15m'],

    /*
    |--------------------------------------------------------------------------
    | Enrollment Page
    |--------------------------------------------------------------------------
    |
    | Where the keyring.enrolled middleware sends users who still need to add
    | a second factor: your page for setting one up. Null answers 403.
    |
    | "enrollment_except" names more routes they can still reach meanwhile,
    | besides that page and Keyring's own: route names, with * as a wildcard.
    |
    */

    'enrollment_url' => null,

    'enrollment_except' => [],

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
        'cookie_lifetime' => '400d',
        'trust_for' => '30d',
        'report_link_for' => '7d',
        'keep_revoked_for' => '30d',
        'keep_unseen_for' => '365d',
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
    | again. "remember_cookie" names the cookie that ties "remember me" to
    | the session it was ticked for.
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
        'remember_cookie' => 'keyring_remember',
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
    | An email change can be confirmed from its emailed link for
    | "confirmable_for", and undone from the old address for "revertable_for".
    | A second factor only lets a change skip the old address's confirmation
    | once the account has had it for "established_after", and undoing a
    | change removes the sign-in methods newer than that.
    |
    */

    'protected' => [],

    'email_changes' => [
        'confirmable_for' => '24h',
        'revertable_for' => '7d',
        'established_after' => '7d',
        'sign_out_others' => true,
        'keep_ended_for' => '30d',
    ],

    /*
    |--------------------------------------------------------------------------
    | Passwords
    |--------------------------------------------------------------------------
    |
    | At least 8 characters with a second factor and 15 without, any
    | characters, and no composition rules. Bcrypt silently ignores anything
    | past 72 bytes, so with bcrypt longer passwords are rejected rather than
    | truncated.
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
    | Signal scores add up (0-100) into a level. Pick signals and what to do at
    | each level with Keyring::risk()->signals([...])->respond(fn ...). By
    | default: medium asks for another factor, high also notifies, critical
    | refuses the sign in, or on a signed-in request signs out every session.
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
    | `php artisan keyring:prune`.
    |
    */

    'security_log' => [
        'keep_for' => '180d',

        // Shown once as "was this you?" at the next sign in (keyring.alerts).
        'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Pending Logins
    |--------------------------------------------------------------------------
    |
    | How long a half-finished login (password accepted, second factor still
    | needed) stays valid before the user has to start over.
    |
    */

    'pending_logins' => [
        'keep_for' => '10m',
    ],

    /*
    |--------------------------------------------------------------------------
    | Enrollments
    |--------------------------------------------------------------------------
    |
    | How long a user has to finish adding a sign-in method once they start:
    | scanning the QR code, typing the emailed code, touching the key.
    |
    */

    'enrollments' => [
        'keep_for' => '15m',
    ],

    /*
    |--------------------------------------------------------------------------
    | Timebox
    |--------------------------------------------------------------------------
    |
    | Every failed factor verification takes at least this long, so response
    | timing doesn't reveal whether an account exists.
    |
    */

    'timebox' => '250ms',

    /*
    |--------------------------------------------------------------------------
    | Rate Limits
    |--------------------------------------------------------------------------
    |
    | Default attempts per minute, per account and per IP address, and the
    | failures in a row an account's factor allows however slowly they come
    | (null for no cap). At that cap the factor is refused until the count is
    | forgotten ("remember_failures_for"), or for a password until a reset.
    | Factors may declare their own limits.
    |
    | Each lockout lasts twice as long as the one before, up to "longest_lock",
    | or "longest_ip_lock" for a whole IP address. "codes" is how many codes
    | an account can be sent for one factor every "codes_per".
    |
    */

    'limits' => [
        'per_account' => 5,
        'per_ip' => 20,
        'consecutive' => 100,
        'remember_failures_for' => '30d',
        'longest_lock' => '24h',
        'longest_ip_lock' => '15m',
        'codes' => 3,
        'codes_per' => '10m',
    ],

];
