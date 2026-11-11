<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class PasswordChanged extends SecurityNotice
{
    public function subject(): string
    {
        return __('Your password was changed');
    }

    public function intro(): string
    {
        return __('The password for your account was just changed.');
    }
}
