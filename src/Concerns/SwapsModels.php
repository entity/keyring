<?php

declare(strict_types=1);

namespace Keyring\Concerns;

use Illuminate\Database\Eloquent\Model;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;

/**
 * Keyring's models, each replaceable with a subclass of the app's own.
 */
trait SwapsModels
{
    /** @var array<class-string<Model>, class-string<Model>> The app's model for each of Keyring's it replaced. */
    protected array $models = [];

    /**
     * @param  class-string<Authenticator>  $model
     */
    public function useAuthenticatorModel(string $model): static
    {
        return $this->useModel(Authenticator::class, $model);
    }

    /**
     * @return class-string<Authenticator>
     */
    public function authenticatorModel(): string
    {
        return $this->model(Authenticator::class);
    }

    /**
     * @param  class-string<Device>  $model
     */
    public function useDeviceModel(string $model): static
    {
        return $this->useModel(Device::class, $model);
    }

    /**
     * @return class-string<Device>
     */
    public function deviceModel(): string
    {
        return $this->model(Device::class);
    }

    /**
     * @param  class-string<PendingChange>  $model
     */
    public function usePendingChangeModel(string $model): static
    {
        return $this->useModel(PendingChange::class, $model);
    }

    /**
     * @return class-string<PendingChange>
     */
    public function pendingChangeModel(): string
    {
        return $this->model(PendingChange::class);
    }

    /**
     * @param  class-string<SecurityEvent>  $model
     */
    public function useSecurityEventModel(string $model): static
    {
        return $this->useModel(SecurityEvent::class, $model);
    }

    /**
     * @return class-string<SecurityEvent>
     */
    public function securityEventModel(): string
    {
        return $this->model(SecurityEvent::class);
    }

    /**
     * @template TModel of Model
     *
     * @param  class-string<TModel>  $base
     * @param  class-string<TModel>  $model
     */
    protected function useModel(string $base, string $model): static
    {
        $this->models[$base] = $model;

        return $this;
    }

    /**
     * The app's model in place of one of Keyring's, or Keyring's own.
     *
     * @template TModel of Model
     *
     * @param  class-string<TModel>  $base
     * @return class-string<TModel>
     */
    protected function model(string $base): string
    {
        /** @var class-string<TModel> $model */
        $model = $this->models[$base] ?? $base;

        return $model;
    }
}
