<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Container\Attributes\Singleton;
use Illuminate\Support\Manager;
use Keyring\Contracts\SessionRegistry;

/**
 * Picks the session registry driver. Add your own with
 * app(SessionRegistryManager::class)->extend('name', fn ($app) => ...).
 *
 * Every driver comes wrapped in an AnnouncingSessionRegistry, Keyring's and
 * yours alike, so each session that ends through it is announced.
 *
 * @mixin SessionRegistry
 */
#[Singleton]
class SessionRegistryManager extends Manager
{
    public function getDefaultDriver(): string
    {
        return $this->config->get('keyring.sessions.driver');
    }

    /**
     * @param  string  $driver
     */
    protected function createDriver($driver): AnnouncingSessionRegistry
    {
        $registry = parent::createDriver($driver);

        // A driver of yours may be one of these already, built from another.
        return $registry instanceof AnnouncingSessionRegistry ? $registry : new AnnouncingSessionRegistry($registry);
    }

    protected function createDatabaseDriver(): SessionRegistry
    {
        return new DatabaseSessionRegistry(
            $this->container->make('db')->connection($this->config->get('keyring.sessions.connection')),
            $this->config->get('keyring.sessions.table'),
        );
    }

    protected function createCacheDriver(): SessionRegistry
    {
        return new CacheSessionRegistry(
            $this->container->make('cache')->store($this->config->get('keyring.sessions.store')),
        );
    }
}
