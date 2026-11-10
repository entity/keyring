<?php

namespace Keyring\Concerns;

use Keyring\Contracts\CreatesNewUsers;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Contracts\ValidatesEmailChanges;

/**
 * The app's own actions for creating users and changing what they sign in
 * with. Keyring does the security work around each.
 */
trait RegistersActions
{
    /**
     * Your action that validates and creates users at registration.
     *
     * @param  class-string<CreatesNewUsers>  $action
     */
    public function createUsersUsing(string $action): static
    {
        return $this->useAction(CreatesNewUsers::class, $action);
    }

    /**
     * Your action that validates and saves a password from a reset link.
     *
     * @param  class-string<ResetsUserPasswords>  $action
     */
    public function resetUserPasswordsUsing(string $action): static
    {
        return $this->useAction(ResetsUserPasswords::class, $action);
    }

    /**
     * Your action that validates and saves a password the user changed.
     *
     * @param  class-string<UpdatesUserPasswords>  $action
     */
    public function updateUserPasswordsUsing(string $action): static
    {
        return $this->useAction(UpdatesUserPasswords::class, $action);
    }

    /**
     * Your action that validates a requested email change.
     *
     * @param  class-string<ValidatesEmailChanges>  $action
     */
    public function validateEmailChangesUsing(string $action): static
    {
        return $this->useAction(ValidatesEmailChanges::class, $action);
    }

    /**
     * @param  class-string  $contract
     * @param  class-string  $action
     */
    protected function useAction(string $contract, string $action): static
    {
        app()->singleton($contract, $action);

        return $this;
    }
}
