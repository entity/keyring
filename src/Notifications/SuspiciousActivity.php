<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class SuspiciousActivity extends SecurityNotice
{
    public function subject(): string
    {
        return __('Unusual activity on your account');
    }

    public function intro(): string
    {
        return __('We noticed something unusual and asked for extra verification: :reasons', ['reasons' => $this->reasons]);
    }
}
