<?php

namespace Keyring\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Keyring\Changes\ReservedAddresses;

/**
 * Refuses an address that's reserved for its previous owner while their
 * email change can still be reverted. Use it next to Rule::unique() wherever
 * users are created or given a new address.
 */
class UnreservedAddress implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (is_string($value) && app(ReservedAddresses::class)->has($value)) {
            $fail('validation.unique')->translate();
        }
    }
}
