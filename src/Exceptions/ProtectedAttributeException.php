<?php

namespace Keyring\Exceptions;

use Illuminate\Database\Eloquent\Model;
use LogicException;

class ProtectedAttributeException extends LogicException
{
    /**
     * @param  list<string>  $attributes
     */
    public static function for(Model $model, array $attributes): self
    {
        return new self(sprintf(
            'Attempted to change protected attribute(s) [%s] on [%s] outside a Keyring flow. '
            .'Use Keyring\'s email/password change flows, or Keyring::withoutProtection() for trusted admin tooling.',
            implode(', ', $attributes),
            $model::class,
        ));
    }
}
