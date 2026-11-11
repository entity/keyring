<?php

declare(strict_types=1);

namespace Keyring\Enums;

/**
 * Why a user is being asked to verify a factor. Login and step-up share the
 * same challenge flow.
 */
enum Purpose: string
{
    case Login = 'login';

    case Confirm = 'confirm';
}
