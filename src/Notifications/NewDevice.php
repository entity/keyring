<?php

declare(strict_types=1);

namespace Keyring\Notifications;

class NewDevice extends SecurityNotice
{
    public function subject(): string
    {
        return __('New sign-in to your account');
    }

    public function intro(): string
    {
        return __('Your account was just signed in to from a device we haven\'t seen before.');
    }

    public function action(): ?string
    {
        return __('This wasn\'t me');
    }
}
