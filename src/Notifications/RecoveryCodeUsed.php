<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class RecoveryCodeUsed extends SecurityNotice
{
    public function subject(): string
    {
        return __('A recovery code was used');
    }

    public function intro(): string
    {
        return __('A recovery code was used to sign in to your account. You have :remaining left.', ['remaining' => $this->remaining]);
    }
}
