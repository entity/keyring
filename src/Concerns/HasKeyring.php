<?php

namespace Keyring\Concerns;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Keyring\Changes\ReservedAddresses;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
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
     * Protected attributes (email, password) can only change through Keyring,
     * and nobody can take an address an email change may still revert to.
     */
    public static function bootHasKeyring(): void
    {
        static::creating(fn (self $user) => app(ReservedAddresses::class)->guard($user));
        static::updating(function (self $user) {
            Keyring::guardProtectedAttributes($user);
            app(ReservedAddresses::class)->guard($user);
        });

        // Signed out everywhere either way. A soft deleted user keeps their
        // sign-in methods in case they're restored; once really gone, they go
        // too, so a passkey can be registered again on a new account.
        static::deleted(function (self $user) {
            app(Sessions::class)->registry()->revokeAll($user);

            if (method_exists($user, 'isForceDeleting') && ! $user->isForceDeleting()) {
                return;
            }

            $user->authenticators()->delete();
            $user->devices()->delete();
            Keyring::pendingChangeModel()::query()->ownedBy($user)->delete();
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
        return $this->morphMany(Keyring::deviceModel(), 'authenticatable');
    }

    /**
     * Everything the user can sign in with.
     */
    protected function keyring(): Attribute
    {
        return Attribute::get(fn () => Keyring::for($this))->shouldCache();
    }
}
