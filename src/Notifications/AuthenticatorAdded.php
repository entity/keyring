<?php

declare(strict_types=1);

namespace Keyring\Notifications;

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
}
