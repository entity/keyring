<?php

declare(strict_types=1);

namespace Keyring\Notifications;

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
}
