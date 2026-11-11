<?php

declare(strict_types=1);

namespace Keyring\Risk;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\Eloquent\Model;

/**
 * Temporary sign-in locks placed by risk actions. A password reset lifts
 * them, so a lock can't be used to keep the owner out for good.
 */
class RiskLocks
{
    public function __construct(
        protected Repository $cache,
    ) {}

    public function lock(Authenticatable $user, int $seconds): void
    {
        $this->cache->put($this->key($user), true, $seconds);
    }

    public function locked(Authenticatable $user): bool
    {
        return $this->cache->has($this->key($user));
    }

    public function unlock(Authenticatable $user): void
    {
        $this->cache->forget($this->key($user));
    }

    /**
     * By the model as well as the ID: two user models can have the same IDs,
     * and a lock on one account isn't a lock on the other. Hashed, so it
     * stays short whatever the model is called.
     */
    protected function key(Authenticatable $user): string
    {
        return 'keyring:risk-lock:'.sha1(($user instanceof Model ? $user->getMorphClass() : $user::class).'|'.$user->getAuthIdentifier());
    }
}
