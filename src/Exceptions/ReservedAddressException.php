<?php

namespace Keyring\Exceptions;

use Illuminate\Database\Eloquent\Model;
use LogicException;

class ReservedAddressException extends LogicException
{
    public static function for(Model $model, string $attribute): self
    {
        return new self(sprintf(
            'The [%s] given to [%s] is reserved: an email change that can still be reverted replaced it. '
            .'Validate new addresses with Keyring\Rules\UnreservedAddress.',
            $attribute,
            $model::class,
        ));
    }
}
