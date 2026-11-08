<?php

namespace Keyring\Enums;

/**
 * Why a user is being asked to verify a factor. Login, step-up and account
 * recovery all share the same challenge flow.
 */
enum Purpose: string
{
    case Login = 'login';

    case Confirm = 'confirm';

    case Recovery = 'recovery';
}
