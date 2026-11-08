<?php

namespace Keyring\Risk;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Repository;

/**
 * Temporary sign-in locks placed by risk actions. Password reset still works
 * while locked, so a lock can't be used to keep someone out for good.
 */
class RiskLocks
{
    public function __construct(
        protected Repository $cache,
    ) {}

    public function lock(Authenticatable $user, int $seconds): void
    {
        $this->cache->put($this->key($user), now()->addSeconds($seconds)->getTimestamp(), $seconds);
    }

    public function locked(Authenticatable $user): bool
    {
        return (int) $this->cache->get($this->key($user), 0) > now()->getTimestamp();
    }

    public function unlock(Authenticatable $user): void
    {
        $this->cache->forget($this->key($user));
    }

    protected function key(Authenticatable $user): string
    {
        return 'keyring:risk-lock:'.$user->getAuthIdentifier();
    }
}
