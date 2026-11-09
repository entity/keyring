<?php

use Keyring\Features;

return [

    /*
    |--------------------------------------------------------------------------
    | Guard, Username and Home
    |--------------------------------------------------------------------------
    |
    | The guard Keyring signs users in to, the attribute they sign in with,
    | and where they go once they have.
    |
    */

    'guard' => 'web',

    'username' => 'email',

    'home' => '/dashboard',

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
        Features::emailVerification(),
        Features::updatePasswords(),
        Features::manageAuthenticators(),
        Features::devices(),
        Features::emailChanges(),
        Features::securityLog(),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Emails
    |--------------------------------------------------------------------------
    |
    | The notices Keyring sends users about their account. These four are the
    | ones NIST SP 800-63B asks for. The others: new_device,
    | second_factor_failed, suspicious_activity and clone_suspected.
    |
    */

    'notifications' => [
        'password_changed',
        'authenticator_added',
        'authenticator_removed',
        'recovery_code_used',
    ],

    /*
    |--------------------------------------------------------------------------
    | Everything Else
    |--------------------------------------------------------------------------
    |
    | Sessions, passwords, devices, rate limits and the rest keep Keyring's
    | defaults. "Configuration" in the docs lists every option: copy one in
    | here to change it.
    |
    */

];
