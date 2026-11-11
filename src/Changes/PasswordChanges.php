<?php

declare(strict_types=1);

namespace Keyring\Changes;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Keyring\Events\PasswordChanged;
use Keyring\Events\PasswordReset;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\Sessions;
use Keyring\Support\PasswordRules;
use Keyring\Support\Throttle;
use LogicException;

/**
 * What always happens around a new password, whatever the app's action does
 * to validate and save it. Whoever knew the old one shouldn't keep what they
 * did with it: pending email changes are cancelled, outstanding reset links
 * stop working, and other sessions are signed out.
 */
class PasswordChanges
{
    public function __construct(
        protected ProtectedAttributes $protection,
        protected Sessions $sessions,
        protected EmailChanges $emailChanges,
        protected RiskLocks $locks,
        protected ResetTokens $resetTokens,
        protected Throttle $throttle,
        protected PasswordHolds $holds,
    ) {}

    /**
     * The signed-in user chose a new password, saved by $save. Every other
     * session is signed out, unless they asked to stay signed in elsewhere.
     * Guesses at the old password say nothing about the new one, so the
     * account's sign-in limits start over, as after a reset: a password the
     * cap had got refused elsewhere works again.
     *
     * $current is the password they proved to get here, when they have one.
     * Saving it again as the new one is refused: nothing would have changed,
     * and a user held until they change it would be let go.
     *
     * @param  Closure(): void  $save
     *
     * @throws ValidationException
     */
    public function change(Authenticatable&Model $user, Closure $save, ?string $currentSession, bool $signOutOthers = true, #[\SensitiveParameter] ?string $current = null): void
    {
        if (! $this->save($user, $save, old: $current)) {
            throw ValidationException::withMessages(['password' => __('keyring::keyring.password_unchanged')]);
        }

        $this->sessions->distrustDevices($user);
        $this->throttle->clearAccount($user);

        if ($signOutOthers) {
            $this->sessions->signOutEverywhere($user, except: $currentSession);
        }

        PasswordChanged::dispatch($user);
    }

    /**
     * The user proved they own the address with a reset link, and $save set
     * the new password. Every session is signed out, and risk locks and the
     * account's throttle locks are lifted so a lock can't keep the owner out
     * for good.
     *
     * $new is the password they sent. When it's the one the account already
     * had, the reset goes through like any other, so the form doesn't tell a
     * link's holder that a guess was right, but a hold stays: the password
     * it's waiting to see the back of is still the password.
     *
     * @param  Closure(): void  $save
     */
    public function reset(Authenticatable&Model $user, Closure $save, #[\SensitiveParameter] ?string $new = null): void
    {
        $this->save($user, $save, new: $new, keepHold: true);
        $this->sessions->signOutEverywhere($user);
        $this->locks->unlock($user);
        $this->throttle->clearAccount($user);

        PasswordReset::dispatch($user);
    }

    /**
     * Run the app's action as a Keyring flow that may change the password and
     * nothing else, and make sure it did: everything that follows (signing
     * out, lifting locks, telling the user) assumes the password changed.
     *
     * A new hash isn't a new password: the same one hashes differently every
     * time. So the answer is whether the password itself changed, as far as
     * can be told: from $old, a password known to have been the account's,
     * checked against the new hash, or from $new, the one that was sent,
     * checked against the old hash. With $keepHold the rest still happens
     * for a password that didn't change, and only the hold is kept.
     *
     * @param  Closure(): void  $save
     */
    protected function save(Authenticatable&Model $user, Closure $save, #[\SensitiveParameter] ?string $old = null, #[\SensitiveParameter] ?string $new = null, bool $keepHold = false): bool
    {
        $before = $user->getAuthPassword();

        $this->protection->changing($save, only: [$user->getAuthPasswordName()]);

        $after = $user->newQuery()->whereKey($user->getKey())->first()?->getAuthPassword();

        if ($after === $before) {
            throw new LogicException('The password action returned without saving a new password. Throw a ValidationException to refuse it.');
        }

        $changed = ! $this->matches($old, $after) && ! $this->matches($new, $before);

        if (! $changed && ! $keepHold) {
            return false;
        }

        $this->emailChanges->cancel($user);
        $this->resetTokens->forget($user);

        // A user held until they chose a new password just did.
        if ($changed) {
            $this->holds->lift($user);
        }

        return $changed;
    }

    protected function matches(#[\SensitiveParameter] ?string $password, ?string $hash): bool
    {
        return $password !== null && filled($hash) && Hash::check(PasswordRules::forVerifying($password, $hash), $hash);
    }
}
