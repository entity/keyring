<?php

namespace Keyring\Exceptions;

use Illuminate\Contracts\Auth\Authenticatable;
use LogicException;

class UnregisteredFactor extends LogicException
{
    /**
     * @param  list<string>  $factors
     */
    public static function for(Authenticatable $user, array $factors): self
    {
        return new self(sprintf(
            'User [%s] has authenticators for [%s], which isn\'t registered, so Keyring refused their sign in rather than skip them. Add it to Keyring::factors(), or delete those authenticators.',
            $user->getAuthIdentifier(),
            implode(', ', $factors),
        ));
    }
}
