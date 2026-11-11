<?php

declare(strict_types=1);

namespace Keyring\Risk;

enum Checkpoint: string
{
    /** While signing in: every signal can run. */
    case Login = 'login';

    /** On signed-in requests: only cheap signals. */
    case Request = 'request';
}
