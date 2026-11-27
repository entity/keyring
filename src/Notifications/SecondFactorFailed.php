<?php

declare(strict_types=1);

namespace Keyring\Notifications;

/**
 * A later step of a login failed once the first had passed. $name is the
 * sign-in method that first step used when it wasn't the password, such as
 * a linked identity provider, and null after the password.
 */
class SecondFactorFailed extends SecurityNotice
{
    public function subject(): string
    {
        return $this->name === null
            ? __('Someone entered your password')
            : __('Someone started signing in to your account');
    }

    public function intro(): string
    {
        return $this->name === null
            ? __('Someone signed in with your password but couldn\'t complete the second step. If this wasn\'t you, your password is probably known to someone else.')
            : __('Someone signed in with :name but couldn\'t complete the second step. If this wasn\'t you, someone else can probably sign in to that account.', ['name' => $this->name]);
    }
}
