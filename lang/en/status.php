<?php

declare(strict_types=1);

// Messages for the status slugs Keyring flashes (and returns as "status"
// in JSON). Pages can show these, or use the slug to decide for themselves.

return [
    'authenticator-added' => 'Sign-in method added.',
    'authenticator-removed' => 'Sign-in method removed.',
    'authenticator-updated' => 'Sign-in method updated.',
    'change-password' => 'Choose a new password to carry on.',
    'code-sent' => 'We sent you a new code.',
    'device-reported' => 'We\'ve signed that device out. We recommend changing your password now.',
    'device-revoked' => 'That device has been signed out.',
    'email-change-cancelled' => 'The email change was cancelled.',
    'email-change-confirmed' => 'Thanks! The change applies once the other address confirms too.',
    'email-change-invalid' => 'That link has expired or was already used.',
    'email-change-requested' => 'Check your inbox to confirm the new address.',
    'email-change-reverted' => 'Your old email address is back and every session was signed out. Please reset your password.',
    'email-changed' => 'Your email address has been changed.',
    'enroll-first' => 'Set up another way to sign in, like an authenticator app or a passkey, before going on.',
    'enrollment-started' => 'Finish setting up your new sign-in method.',
    'password-reset' => 'Your password has been reset. Please sign in.',
    'password-updated' => 'Your password has been changed.',
    'registered' => 'Your account has been created. You can sign in once it\'s ready.',
    'reset-link-sent' => 'If that address has an account, we\'ve emailed a link to reset the password.',
    'session-revoked' => 'That session has been signed out.',
    'sessions-revoked' => 'You\'ve been signed out everywhere else.',
    'signed-out' => 'You\'ve been signed out. Please sign in again.',
    'verification-link-sent' => 'We\'ve emailed you a new verification link.',
];
