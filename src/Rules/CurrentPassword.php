<?php

declare(strict_types=1);

namespace Keyring\Rules;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Hash;
use Keyring\Support\PasswordRules;

/**
 * The user's current password, like Laravel's current_password rule. A
 * password longer than bcrypt reads is refused instead of passing on its
 * first 72 bytes.
 */
class CurrentPassword implements ValidationRule
{
    public function __construct(
        protected Authenticatable $user,
    ) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $hash = $this->user->getAuthPassword();

        if (! is_string($value) || ! Hash::check(PasswordRules::forVerifying($value, $hash), $hash)) {
            $fail('validation.current_password')->translate();
        }
    }
}
