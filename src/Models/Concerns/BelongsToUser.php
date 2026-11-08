<?php

namespace Keyring\Models\Concerns;

use Illuminate\Contracts\Auth\Authenticatable;
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
}
