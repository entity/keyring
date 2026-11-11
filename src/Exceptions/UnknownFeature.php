<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Keyring\Features;
use LogicException;

class UnknownFeature extends LogicException
{
    /**
     * @param  list<string>  $features
     */
    public static function in(array $features): self
    {
        return new self(sprintf(
            'Unknown Keyring features in config/keyring.php: [%s]. Use the Features:: methods, which give: %s.',
            implode(', ', $features),
            implode(', ', Features::all()),
        ));
    }
}
