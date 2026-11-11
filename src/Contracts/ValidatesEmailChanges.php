<?php

declare(strict_types=1);

namespace Keyring\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

/**
 * Your code, published to app/Actions/Keyring/ValidateEmailChange.php by
 * keyring:install.
 */
interface ValidatesEmailChanges
{
    /**
     * Validate a request to change the email address and return the new
     * address. Keyring confirms it with both addresses before it
     * applies, so don't check here whether the address is taken: that
     * would tell anyone who asks.
     *
     * @param  array<string, mixed>  $input
     */
    public function validate(Authenticatable&Model $user, array $input): string;
}
