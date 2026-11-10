<?php

namespace Keyring\Sessions;

use Illuminate\Container\Attributes\Singleton;
use Illuminate\Support\Manager;
use Keyring\Contracts\SessionRegistry;

/**
 * Picks the session registry driver. Add your own with
 * app(SessionRegistryManager::class)->extend('name', fn ($app) => ...).
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
