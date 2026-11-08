<?php

return [
    'footer' => 'If this wasn\'t you, change your password and check your sign-in methods straight away.',

    'new_device' => [
        'subject' => 'New sign-in to your account',
        'intro' => 'Your account was just signed in to from a device we haven\'t seen before.',
        'action' => 'This wasn\'t me',
    ],
    'password_changed' => [
        'subject' => 'Your password was changed',
        'intro' => 'The password for your account was just changed.',
    ],
    'authenticator_added' => [
        'subject' => 'A sign-in method was added',
        'intro' => '":name" was added as a way to sign in to your account.',
    ],
    'authenticator_removed' => [
        'subject' => 'A sign-in method was removed',
        'intro' => '":name" was removed from your account.',
    ],
    'second_factor_failed' => [
        'subject' => 'Someone entered your password',
        'intro' => 'Someone signed in with your password but couldn\'t complete the second step. If this wasn\'t you, your password is probably known to someone else.',
    ],
    'recovery_code_used' => [
        'subject' => 'A recovery code was used',
        'intro' => 'A recovery code was used to sign in to your account. You have :remaining left.',
    ],
    'suspicious_activity' => [
        'subject' => 'Unusual activity on your account',
        'intro' => 'We noticed something unusual and asked for extra verification: :reasons',
    ],
    'clone_suspected' => [
        'subject' => 'A security key may have been copied',
        'intro' => '":name" answered with an out-of-date counter, which can mean it was copied. We refused the sign-in.',
    ],
];
