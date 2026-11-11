<?php

declare(strict_types=1);

namespace Keyring\Models\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Str;
use Keyring\Events\AccessRefused;

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
     * Refuse a request for one of these that the user doesn't have. The
     * answer is the 404 a missing one gets, so it doesn't say whether the ID
     * is someone else's, and the attempt goes on record.
     *
     * @throws ModelNotFoundException<static>
     */
    public static function refuse(Authenticatable&Model $user, string $id): never
    {
        // Named after Keyring's model, whichever of the app's stands in for it.
        AccessRefused::dispatch($user, Str::snake(class_basename(self::class)), $id);

        throw new ModelNotFoundException()->setModel(static::class, $id);
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
