<?php

namespace Keyring\Changes;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Keyring\Events\PasswordChanged;
use Keyring\Events\PasswordReset;
use Keyring\KeyringManager;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\Sessions;

/**
 * What always happens around a new password, whatever the app's action does
 * to validate and save it. Whoever knew the old one shouldn't keep what they
 * did with it: pending email changes are cancelled, and other sessions are
 * signed out.
 */
class PasswordChanges
{
    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected EmailChanges $emailChanges,
        protected RiskLocks $locks,
    ) {}

    /**
     * The signed-in user chose a new password, saved by $save. Every other
     * session is signed out, unless they asked to stay signed in elsewhere.
     *
     * @param  Closure(): void  $save
     */
    public function change(Authenticatable&Model $user, Closure $save, ?string $currentSession, bool $signOutOthers = true): void
    {
        $this->save($user, $save);

        if ($signOutOthers) {
            $this->sessions->revokeAll($user, except: $currentSession);
        }

        PasswordChanged::dispatch($user);
    }

    /**
     * The user proved they own the address with a reset link, and $save set
     * the new password. Every session is signed out, and risk locks are
     * lifted so a lock can't keep the owner out for good.
     *
     * @param  Closure(): void  $save
     */
    public function reset(Authenticatable&Model $user, Closure $save): void
    {
        $this->save($user, $save);
        $this->sessions->revokeAll($user);
        $this->locks->unlock($user);

        PasswordReset::dispatch($user);
    }

    /**
     * Run the app's action as a Keyring flow, so it may change the password.
     *
     * @param  Closure(): void  $save
     */
    protected function save(Authenticatable&Model $user, Closure $save): void
    {
        $this->keyring->changing($save);

        $this->emailChanges->cancel($user);
    }
}
