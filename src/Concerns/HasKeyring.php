<?php

namespace Keyring\Concerns;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\UserKeyring;

/**
 * Add to your User model.
 *
 * @property-read UserKeyring $keyring
 */
trait HasKeyring
{
    /**
     * @return MorphMany<Authenticator, $this>
     */
    public function authenticators(): MorphMany
    {
        return $this->morphMany(Keyring::authenticatorModel(), 'authenticatable');
    }

    /**
     * @return MorphMany<Device, $this>
     */
    public function devices(): MorphMany
    {
        return $this->morphMany(Device::class, 'authenticatable');
    }

    /**
     * Everything the user can sign in with.
     */
    protected function keyring(): Attribute
    {
        return Attribute::get(fn () => Keyring::for($this))->shouldCache();
    }
}
