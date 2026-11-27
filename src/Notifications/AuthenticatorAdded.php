<?php

declare(strict_types=1);

namespace Keyring\Notifications;

/**
 * Links to "authenticators_url" when the app has one. A method that was
 * added recently can always be removed, even while the account's others
 * can't, so the owner can take away one they didn't add.
 */
class AuthenticatorAdded extends SecurityNotice
{
    public function subject(): string
    {
        return __('A sign-in method was added');
    }

    public function intro(): string
    {
        return __('":name" was added as a way to sign in to your account.', ['name' => $this->name]);
    }

    public function action(): ?string
    {
        return __('Review your sign-in methods');
    }

    public function ifNotYou(): string
    {
        return __('If you didn\'t add it, someone else may be signed in to your account. Remove it, sign out of your account everywhere, and change your password straight away.');
    }
}
