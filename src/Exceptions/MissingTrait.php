<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Keyring\Concerns\HasKeyring;
use LogicException;

class MissingTrait extends LogicException
{
    public static function on(string $model): self
    {
        return new self(sprintf(
            '[%s] needs the [%s] trait. Without it Keyring can\'t protect the email and password, or sign the user out when they\'re deleted.',
            $model,
            HasKeyring::class,
        ));
    }
}
