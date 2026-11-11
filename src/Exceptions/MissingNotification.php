<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use LogicException;

class MissingNotification extends LogicException
{
    public static function for(string $type): self
    {
        return new self(sprintf(
            'No notification is registered for [%1$s], which this needs to send. Keyring::notifications([...]) set \'%1$s\' to null: give it a notification class there, or leave it out to send Keyring\'s own.',
            $type,
        ));
    }
}
