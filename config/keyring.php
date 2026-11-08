<?php

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
