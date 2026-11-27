<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use Illuminate\Validation\ValidationException;

/**
 * Adding a factor took the user's password, typed for it, and it wasn't
 * confirmed: see AuthenticatorChanges::needsPassword(). It's a validation
 * error on "password", like any other.
 */
class PasswordRequired extends ValidationException {}
