<?php

namespace Keyring\Changes;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Keyring\Events\PasswordChanged;
use Keyring\Events\PasswordReset;
use Keyring\KeyringManager;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\Sessions;

/**
 * Setting a new password, the same way wherever it happens. Whoever knew the
 * old one shouldn't keep what they did with it: pending email changes are
 * cancelled, and other sessions are signed out.
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
     * The signed-in user chose a new password. Every other session is signed
     * out, unless they asked to stay signed in elsewhere.
     */
    public function change(Authenticatable&Model $user, string $password, ?string $currentSession, bool $signOutOthers = true): void
    {
        $this->update($user, $password);

        if ($signOutOthers) {
            $this->sessions->revokeAll($user, except: $currentSession);
        }

        PasswordChanged::dispatch($user);
    }

    /**
     * The user proved they own the address with a reset link. Every session
     * is signed out, and risk locks are lifted so a lock can't keep the owner
     * out for good.
     */
    public function reset(Authenticatable&Model $user, string $password): void
    {
        $this->update($user, $password);
        $this->sessions->revokeAll($user);
        $this->locks->unlock($user);

        PasswordReset::dispatch($user);
    }

    protected function update(Authenticatable&Model $user, string $password): void
    {
        $this->keyring->changing(fn () => $user->forceFill(['password' => Hash::make($password)])->save());

        $this->emailChanges->cancel($user);
    }
}
