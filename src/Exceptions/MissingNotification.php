<?php

namespace Keyring\Exceptions;

use LogicException;

class MissingNotification extends LogicException
{
    public static function for(string $type): self
    {
        return new self(sprintf(
            'No notification is registered for [%1$s], which this needs to send. Add \'%1$s\' to Keyring::notifications([...]) in your KeyringServiceProvider; keyring:install publishes one to app/Notifications/Keyring.',
            $type,
        ));
    }
}
