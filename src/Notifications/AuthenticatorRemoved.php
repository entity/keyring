<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class AuthenticatorRemoved extends SecurityNotice
{
    public function subject(): string
    {
        return __('A sign-in method was removed');
    }

    public function intro(): string
    {
        return __('":name" was removed from your account.', ['name' => $this->name]);
    }
}
