<?php

return [
    'footer' => 'If this wasn\'t you, change your password and check your sign-in methods straight away.',

    'details' => [
        'when' => 'When',
        'device' => 'Device',
        'ip' => 'IP address',
    ],

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

    'email_changed' => [
        'subject' => 'Your email address was changed',
        'intro' => 'The email address on your account was just changed. You now sign in and recover your account with the new address. To undo it, use the link in the email we sent to the old address when the change was requested.',
    ],
    'email_change_reverted' => [
        'subject' => 'Your email address change was undone',
        'intro' => 'A change to the email address on your account was just undone, and you were signed out everywhere.',
    ],

    'verification_code' => [
        'subject' => 'Your verification code',
        'intro' => 'Your verification code is:',
        'expires' => 'It expires in :minutes minutes.',
        'outro' => 'If you didn\'t try to sign in, someone may know your password. Please change it.',
        'outro_enrolling' => 'If you didn\'t ask to add this email as a sign-in method, someone may be signed in to your account. Please change your password.',
    ],
    'confirm_email_change' => [
        'subject' => 'Confirm your new email address',
        'intro' => 'Please confirm this is the new email address for your account.',
        'action' => 'Confirm email address',
        'expires' => 'This link expires :when.',
        'outro' => 'If you didn\'t ask for this, you can ignore this email.',
    ],
    'email_change_notice' => [
        'subject' => 'Your email address is being changed',
        'intro' => 'Someone asked to change the email address on your account to :email.',
        'confirm' => 'To finish the change, confirm it from this address too.',
        'action' => 'Confirm the change',
        'revert' => 'Wasn\'t you? This link cancels the change and signs you out everywhere:',
    ],
    'email_address_in_use' => [
        'subject' => 'Someone tried to use your email address',
        'intro' => 'Someone tried to change another account\'s email address to this one. This address already has an account, so nothing was changed.',
        'outro' => 'If this was you, sign in to your existing account instead. Otherwise, you can ignore this email.',
    ],
];
