<?php

declare(strict_types=1);

use Keyring\Devices\NullLocator;
use Keyring\Features;
use Keyring\Http\Middleware\AddSecurityHeaders;

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
    | it needs, only once it's here. Take the security log out and its
    | events are written to your app's log instead.
    |
    */

    'features' => [
        Features::registration(),
        Features::resetPasswords(),
        Features::securityLog(),
        // Features::emailVerification(),
        // Features::updatePasswords(),
        // Features::manageAuthenticators(),
        // Features::devices(),
        // Features::emailChanges(),
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
    | false to register them yourself with Keyring::routes(). AddSecurityHeaders
    | keeps auth pages out of caches, their URLs out of Referer headers and
    | their responses from being read as another content type.
    |
    */

    'routes' => true,

    'prefix' => '',

    'domain' => null,

    'middleware' => ['web', AddSecurityHeaders::class],

    /*
    |--------------------------------------------------------------------------
    | WebAuthn (Passkeys & Security Keys)
    |--------------------------------------------------------------------------
    |
    | The relying party ID defaults to your APP_URL host, and the allowed
    | origins to your APP_URL. The timeout is how long the browser waits.
    | "login_options_for" is how long the challenge for a usernameless sign in
    | can be answered: the login page asks for one as it loads, for autofill.
    |
    | "attestation_roots" are the root certificates a key's attestation has
    | to chain to, for a factor set up with requireAttestation(): PEM
    | certificates, or paths to PEM files.
    |
    | "algorithms" are the signatures keys may use, in order of preference:
    | ES256, EdDSA and RS256. RS256 is all some Windows Hello setups sign
    | with, and is left out because OWASP ASVS doesn't approve it. With it
    | on, an RSA key shorter than "minimum_rsa_bits" is refused (2048 at
    | the least).
    |
    */

    'webauthn' => [
        'relying_party' => [
            'id' => env('KEYRING_WEBAUTHN_RP_ID'),
            'name' => env('KEYRING_WEBAUTHN_RP_NAME'),
        ],
        'origins' => [],
        'timeout' => '60s',
        'login_options_for' => '5m',
        'attestation_roots' => [],
        'algorithms' => ['ES256', 'EdDSA'],
        'minimum_rsa_bits' => 2048,
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
    | Devices are recognised by a long-lived cookie. With "cookie" null it's
    | named keyring_device, and __Host-keyring_device once the app is served
    | over HTTPS; a name you set is used exactly as it is. "trust_for" enables
    | the "don't ask again on this device" option (set to null to turn it off).
    | A trusted device is only an input to your policy, never a factor.
    | An account keeps its "limit" most recently seen devices (null for no
    | limit): a new one beyond that takes the place of the oldest.
    |
    */

    'devices' => [
        'cookie' => null,
        'cookie_lifetime' => '400d',
        'limit' => 50,
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
    | the session it was ticked for: null is keyring_remember, prefixed over
    | HTTPS like the device cookie. Each one works once and is replaced.
    | For "remember_grace" a browser's other requests, sent with the one
    | that used it, are still let in on the same session. Used after that,
    | the session ends for everyone holding it.
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
        'remember_cookie' => null,
        'remember_grace' => '10s',
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
    | characters, and no composition rules. Neither minimum can go below 8:
    | Keyring throws on a lower one rather than raise it quietly.
    |
    | "max" is in characters, and is only reached with a hasher that reads a
    | whole password. Bcrypt, Laravel's default, silently ignores anything
    | past 72 bytes, so with bcrypt Keyring refuses a longer password rather
    | than truncate it: the real limit is then 72 bytes, which is 72 plain
    | characters but only 36 accented or Cyrillic ones, 24 Chinese, Japanese
    | or Korean ones, or 18 emoji. Set HASH_DRIVER=argon2id to take every
    | password up to "max", as OWASP ASVS 6.2.9 asks (at least 64 characters).
    |
    | "uncompromised" checks new passwords against Have I Been Pwned over the
    | network. Null runs it in production only, so local and test runs make
    | no network calls. Laravel's check lets a password through when the
    | service can't be reached, which leaves only the list of common
    | passwords that ships with Keyring. Set "refuse_unchecked" to refuse
    | the password instead, and ask the user to try again.
    |
    | "context" is your list of words a password mustn't be made up of: names
    | of your organisation, products, systems, projects and teams. Your app's
    | name, and each user's name and address, are checked without listing.
    |
    */

    'passwords' => [
        'min_with_mfa' => 8,
        'min_without_mfa' => 15,
        'max' => 128,
        'uncompromised' => null,
        'refuse_unchecked' => false,
        'context' => [],
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
    | With Features::securityLog(), sign ins, failures, lockouts, refusals,
    | changes and automatic actions are logged to keyring_events and kept for
    | "keep_for". Without it they're written to the log "channel" instead
    | (null for your default one), so they're always recorded somewhere.
    |
    | "context_key" is where your app keeps a request's ID in Laravel's
    | Context, if it does. Entries carry it, or an ID Keyring makes itself.
    | What's refused can be asked for again without end, so only "refusals"
    | entries of one type are written every "refusals_per" about an account,
    | or from an IP address when nobody is known (null for no limit).
    |
    */

    'security_log' => [
        'keep_for' => '180d',
        'channel' => env('KEYRING_LOG_CHANNEL'),
        'context_key' => 'trace_id',
        'refusals' => 20,
        'refusals_per' => '1h',

        // Shown once as "was this you?" at the next sign in (keyring.alerts).
        'alerts' => ['second_factor_failed', 'device_reported', 'email_change_reverted', 'clone_suspected', 'remember_me_reused'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Pruning
    |--------------------------------------------------------------------------
    |
    | `php artisan keyring:prune` deletes what's past its time: old log
    | entries, devices, ended email changes and ended sessions. Keyring adds
    | it to Laravel's scheduler to run every day at this time, so it happens
    | wherever `schedule:run` does. Null leaves scheduling it to you.
    |
    */

    'prune_at' => '03:00',

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
    | failures in a row one of an account's authenticators allows however
    | slowly they come (100 is the most NIST SP 800-63B allows, null is no
    | cap). They're counted in the database, and at the cap the authenticator
    | is refused until a password reset or Keyring::unlock() clears it, or a
    | second factor is removed and added again. "consecutive_elsewhere" is
    | how many of them browsers the account hasn't signed in from may make,
    | which keeps the rest for the owner's own. Factors may declare their own
    | limits.
    |
    | Each lockout lasts twice as long as the one before, up to "longest_lock",
    | or "longest_ip_lock" for a whole IP address. With "lock_after" set, an
    | account locked out of signing in that many times in a day is refused
    | as it would be at the cap. A typed username nobody has can't be counted
    | in the database, so every name's own failures in a row are counted in
    | the cache as well, for "remember_names_for". "codes" is how many codes
    | an account can be sent for one factor every "codes_per", and "notices"
    | how many security notices of one kind, or email change requests, an
    | account or an address can be sent every "notices_per".
    |
    */

    'limits' => [
        'per_account' => 5,
        'per_ip' => 20,
        'consecutive' => 100,
        'consecutive_elsewhere' => 80,
        'remember_names_for' => '30d',
        'longest_lock' => '24h',
        'longest_ip_lock' => '15m',
        'lock_after' => null,
        'codes' => 3,
        'codes_per' => '10m',
        'notices' => 5,
        'notices_per' => '1h',
    ],

];
