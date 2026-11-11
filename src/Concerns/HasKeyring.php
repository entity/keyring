<?php

namespace Keyring\Concerns;

use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Changes\ReservedAddresses;
use Keyring\Changes\ResetTokens;
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
            app(ProtectedAttributes::class)->guard($user);
            app(ReservedAddresses::class)->guard($user);
        });

        // A reset link is tied to an address, so one sent before the address
        // changed must not work again if it comes back, or for whoever gets
        // it next. Until the save finishes the original still holds it.
        static::updated(function (self $user) {
            if ($user->wasChanged(Keyring::email())) {
                app(ResetTokens::class)->forget((clone $user)->setRawAttributes($user->getRawOriginal()));
            }
        });

        // Signed out, and reset links ended, either way. A soft deleted user
        // keeps their sign-in methods in case they're restored, but nothing
        // that was signed in before gets back in afterwards: "remember me"
        // cookies and trusted devices end too. Once really gone, the sign-in
        // methods go as well, so a passkey can be registered again on a new
        // account.
        static::deleted(function (self $user) {
            app(ResetTokens::class)->forget($user);

            if (method_exists($user, 'isForceDeleting') && ! $user->isForceDeleting()) {
                app(Sessions::class)->signOutEverywhere($user);

                return;
            }

            app(Sessions::class)->registry()->revokeAll($user);
            $user->authenticators()->delete();
            $user->devices()->delete();
            Keyring::pendingChangeModel()::query()->ownedBy($user)->delete();
            Keyring::failureCountModel()::query()->ownedBy($user)->delete();
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
     *
     * @return Attribute<UserKeyring, never>
     */
    protected function keyring(): Attribute
    {
        return Attribute::get(fn () => Keyring::for($this))->shouldCache();
    }
}
