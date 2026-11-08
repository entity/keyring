<?php

namespace Keyring\Exceptions;

use LogicException;

class MissingAction extends LogicException
{
    public static function for(string $contract, string $method): self
    {
        return new self(sprintf(
            'No action is registered for [%s]. Call Keyring::%s() in your KeyringServiceProvider; keyring:install publishes the actions to app/Actions/Keyring.',
            $contract,
            $method,
        ));
    }
}
