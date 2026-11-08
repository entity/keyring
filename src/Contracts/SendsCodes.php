<?php

namespace Keyring\Contracts;

use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;

/**
 * A factor that sends the user a code (email, SMS) when they ask for one.
 * Codes are never sent just by viewing the challenge page, so prefetching
 * or reloading can't trigger a send.
 */
interface SendsCodes extends Factor
{
    public function send(Attempt $attempt, Authenticator $authenticator): void;
}
