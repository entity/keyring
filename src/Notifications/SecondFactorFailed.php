<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class SecondFactorFailed extends SecurityNotice
{
    public function subject(): string
    {
        return __('Someone entered your password');
    }

    public function intro(): string
    {
        return __('Someone signed in with your password but couldn\'t complete the second step. If this wasn\'t you, your password is probably known to someone else.');
    }
}
