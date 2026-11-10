<?php

namespace Keyring\Models\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Keyring's records belong to any authenticatable model, through the
 * "authenticatable" morph.
 */
trait BelongsToUser
{
    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }

    /**
     * The user this belongs to, if they still exist.
     */
    public function user(): (Authenticatable&Model)|null
    {
        $user = $this->authenticatable;

        return $user instanceof Authenticatable ? $user : null;
    }

    /**
     * The user this belongs to, whatever state their account is in: soft
     * deleted, or hidden by a global scope of the app's. For work that has
     * to reach the account itself, like undoing a change to it or signing
     * it out, which a deactivated account needs as much as any other.
     */
    public function owner(): (Authenticatable&Model)|null
    {
        $owner = $this->authenticatable()->withoutGlobalScopes()->first();

        return $owner instanceof Authenticatable ? $owner : null;
    }

    /**
     * @param  Builder<static>  $query
     */
    #[Scope]
    protected function ownedBy(Builder $query, Model $user): void
    {
        $query->whereMorphedTo('authenticatable', $user);
    }
}
