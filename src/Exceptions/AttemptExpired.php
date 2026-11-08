<?php

namespace Keyring\Exceptions;

use RuntimeException;

class AttemptExpired extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('The attempt has expired or its user no longer exists.');
    }
}
