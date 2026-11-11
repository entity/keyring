<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class CloneSuspected extends SecurityNotice
{
    public function subject(): string
    {
        return __('A security key may have been copied');
    }

    public function intro(): string
    {
        return __('":name" answered with an out-of-date counter, which can mean it was copied. We refused the sign-in.', ['name' => $this->name]);
    }
}
