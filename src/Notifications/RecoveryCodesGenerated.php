<?php

declare(strict_types=1);

namespace Keyring\Notifications;

/**
 * Links to "authenticators_url" when the app has one.
 */
class RecoveryCodesGenerated extends SecurityNotice
{
    public function subject(): string
    {
        return __('New recovery codes were made for your account');
    }

    public function intro(): string
    {
        return __('A new set of recovery codes was made for your account. Any codes you saved before no longer work.');
    }

    public function action(): ?string
    {
        return __('Review your sign-in methods');
    }

    public function ifNotYou(): string
    {
        return __('If you didn\'t make them, someone else may be signed in to your account. Sign out of your account everywhere, change your password, and remove any sign-in method you don\'t recognise straight away.');
    }
}
