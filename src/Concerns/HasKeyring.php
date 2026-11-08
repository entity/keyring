<?php

namespace Keyring\Concerns;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Sessions\Sessions;
use Keyring\UserKeyring;

/**
 * Add to your User model.
 *
 * @property-read UserKeyring $keyring
 */
trait HasKeyring
{
    /**
     * Protected attributes (email, password) can only change through Keyring.
     */
    public static function bootHasKeyring(): void
    {
        static::updating(fn (self $user) => Keyring::guardProtectedAttributes($user));

        // Clean up once the user is really gone (not when soft deleted), so a
        // passkey can be registered again on a new account.
        static::deleted(function (self $user) {
            if (method_exists($user, 'isForceDeleting') && ! $user->isForceDeleting()) {
                return;
            }

            app(Sessions::class)->registry()->revokeAll($user);

            $user->authenticators()->delete();
            $user->devices()->delete();
            PendingChange::query()->whereMorphedTo('authenticatable', $user)->delete();
        });
    }

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
