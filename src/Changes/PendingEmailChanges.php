<?php

namespace Keyring\Changes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Expression;
use Keyring\KeyringManager;
use Keyring\Models\PendingChange;

/**
 * The email changes a user has asked for: finding the one waiting for
 * confirmation, and cancelling it. Kept apart from EmailChanges, which
 * runs the whole flow, so that signing out everywhere can cancel a change
 * without needing everything a change needs.
 */
class PendingEmailChanges
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Every email change of the user's, whatever became of it.
     *
     * @return Builder<PendingChange>
     */
    public function of(Authenticatable&Model $user): Builder
    {
        return $this->keyring->pendingChangeModel()::query()->ownedBy($user)->where('attribute', $this->keyring->email());
    }

    /**
     * The change still waiting for confirmation, if there is one.
     */
    public function current(Authenticatable&Model $user): ?PendingChange
    {
        return $this->of($user)->pending()->latest()->first();
    }

    /**
     * Cancel every change still waiting for confirmation. The emailed "this
     * wasn't me" link keeps working until the change would have expired:
     * whoever asked for the change can cancel it too, and that mustn't take
     * the owner's way to undo what they did.
     */
    public function cancel(Authenticatable&Model $user): void
    {
        $this->of($user)->pending()->update([
            'cancelled_at' => now(),
            'revertable_until' => new Expression('expires_at'),
        ]);
    }
}
