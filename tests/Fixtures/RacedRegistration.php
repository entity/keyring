<?php

declare(strict_types=1);

namespace Keyring\Tests\Fixtures;

use Keyring\Login\Registration;

/**
 * Registration as it goes when another request takes the address between
 * the check and the save, as the second of two identical forms sent at once
 * does: the first look finds the address free whatever the table holds, and
 * the users table's unique index is what refuses it.
 */
class RacedRegistration extends Registration
{
    protected bool $looked = false;

    public function taken(string $email): bool
    {
        if ($this->looked) {
            return parent::taken($email);
        }

        $this->looked = true;

        return false;
    }
}
