<?php

namespace Keyring\Changes;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Keyring\Exceptions\ReservedAddressException;
use Keyring\KeyringManager;

/**
 * While an email change can still be reverted, the address it replaced stays
 * with its owner. If someone else could take it meanwhile, the owner's
 * "this wasn't me" link would have nowhere to put it back.
 */
class ReservedAddresses
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Whether the address is held for someone other than the given user.
     */
    public function has(string $address, ?Model $except = null): bool
    {
        $reserved = $this->keyring->pendingChangeModel()::query()
            ->where('attribute', $this->keyring->email())
            ->reserving($address);

        if ($except !== null && $except->exists) {
            $reserved->whereNot(fn (Builder $query) => $query->ownedBy($except));
        }

        return $reserved->exists();
    }

    /**
     * Refuse to save a user with an address held for someone else.
     */
    public function guard(Model $user): void
    {
        $attribute = $this->keyring->email();
        $address = $user->getAttribute($attribute);

        if ($user->isDirty($attribute) && is_string($address) && $this->has($address, except: $user)) {
            throw ReservedAddressException::for($user, $attribute);
        }
    }
}
