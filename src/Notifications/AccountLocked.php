<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class AccountLocked extends SecurityNotice
{
    public function subject(): string
    {
        return __('Your account is locked');
    }

    public function intro(): string
    {
        return __('Too many failed attempts to sign in have locked your account. Reset your password to unlock it.');
    }

    public function action(): ?string
    {
        return __('Reset your password');
    }
}
