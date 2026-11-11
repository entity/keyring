<?php

declare(strict_types=1);

namespace Keyring\Activity;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Events\Dispatcher;
use Keyring\Events;
use Keyring\Factors\RecoveryCodes;
use Keyring\KeyringManager;

/**
 * Turns Keyring's events into security log entries.
 */
class RecordSecurityEvents
{
    public function __construct(
        protected SecurityLog $log,
        protected KeyringManager $keyring,
    ) {}

    /**
     * @return array<class-string, string>
     */
    public function subscribe(Dispatcher $events): array
    {
        return [
            Events\Authenticated::class => 'authenticated',
            Events\Confirmed::class => 'confirmed',
            Events\FactorFailed::class => 'factorFailed',
            Events\Lockout::class => 'lockout',
            Events\AccountLocked::class => 'accountLocked',
            Events\LoggedOut::class => 'loggedOut',
            Events\AuthenticatorAdded::class => 'authenticatorAdded',
            Events\AuthenticatorRemoved::class => 'authenticatorRemoved',
            Events\RecoveryCodeUsed::class => 'recoveryCodeUsed',
            Events\RecoveryCodesGenerated::class => 'recoveryCodesGenerated',
            Events\NewDeviceSignedIn::class => 'newDevice',
            Events\DeviceRevoked::class => 'deviceRevoked',
            Events\SessionsRevoked::class => 'sessionsRevoked',
            Events\SessionEnded::class => 'sessionEnded',
            Events\RememberMeReused::class => 'rememberMeReused',
            Events\EmailChangeRequested::class => 'emailChangeRequested',
            Events\EmailChanged::class => 'emailChanged',
            Events\EmailChangeReverted::class => 'emailChangeReverted',
            Events\PasswordChanged::class => 'passwordChanged',
            Events\PasswordReset::class => 'passwordReset',
            Events\ProtectionBypassed::class => 'protectionBypassed',
            Events\CloneSuspected::class => 'cloneSuspected',
            Events\RiskAssessed::class => 'riskAssessed',
        ];
    }

    public function authenticated(Events\Authenticated $event): void
    {
        $this->log->record('signed_in', $event->user, device: $event->device?->id, meta: [
            'factors' => array_column($event->attempt->verifications, 'factor'),
        ]);
    }

    public function confirmed(Events\Confirmed $event): void
    {
        $this->log->record('confirmed', $event->user, meta: [
            'factors' => array_column($event->attempt->verifications, 'factor'),
        ]);
    }

    /**
     * A failed second factor after a correct password is the classic sign of
     * a stolen password, so it's logged as an alert for the user.
     */
    public function factorFailed(Events\FactorFailed $event): void
    {
        $user = $event->attempt?->user();

        $this->log->record('factor_failed', $user, $event->factor);

        if ($event->afterPassword()) {
            $this->log->record('second_factor_failed', $user, $event->factor);
        }
    }

    public function lockout(Events\Lockout $event): void
    {
        $this->log->record('locked_out', factor: $event->factor, meta: ['retry_after' => $event->retryAfter]);
    }

    public function accountLocked(Events\AccountLocked $event): void
    {
        $this->log->record('account_locked', $event->user, $event->factor);
    }

    public function loggedOut(Events\LoggedOut $event): void
    {
        $this->log->record('signed_out', $event->user);
    }

    public function authenticatorAdded(Events\AuthenticatorAdded $event): void
    {
        $this->log->record('authenticator_added', $event->user, $event->authenticator->factor, meta: ['name' => $event->authenticator->name]);
    }

    public function authenticatorRemoved(Events\AuthenticatorRemoved $event): void
    {
        $this->log->record('authenticator_removed', $event->user, $event->authenticator->factor, meta: ['name' => $event->authenticator->name]);
    }

    public function recoveryCodeUsed(Events\RecoveryCodeUsed $event): void
    {
        $this->log->record('recovery_code_used', $event->authenticator->user(), RecoveryCodes::KEY, meta: ['remaining' => $event->remaining]);
    }

    public function recoveryCodesGenerated(Events\RecoveryCodesGenerated $event): void
    {
        $this->log->record('recovery_codes_generated', $event->user, RecoveryCodes::KEY);
    }

    public function newDevice(Events\NewDeviceSignedIn $event): void
    {
        $this->log->record('new_device', $event->user, device: $event->device->id, meta: ['device' => $event->device->description()]);
    }

    public function deviceRevoked(Events\DeviceRevoked $event): void
    {
        $this->log->record($event->reported ? 'device_reported' : 'device_revoked', $event->user, device: $event->device->id, meta: ['device' => $event->device->description()]);
    }

    public function sessionsRevoked(Events\SessionsRevoked $event): void
    {
        $this->log->record('sessions_revoked', $event->user, meta: ['count' => $event->count]);
    }

    public function sessionEnded(Events\SessionEnded $event): void
    {
        $this->log->record('session_ended', $event->user, meta: ['reason' => $event->reason]);
    }

    /**
     * The entry's own address and browser are the request that brought the
     * used cookie. The device is the one the ended session was on.
     */
    public function rememberMeReused(Events\RememberMeReused $event): void
    {
        $this->log->record('remember_me_reused', $event->user, device: $event->session->deviceId, meta: [
            'device' => $this->keyring->describeDevice($event->session->userAgent),
        ]);
    }

    public function emailChangeRequested(Events\EmailChangeRequested $event): void
    {
        $this->log->record('email_change_requested', $event->user);
    }

    public function emailChanged(Events\EmailChanged $event): void
    {
        $this->log->record('email_changed', $event->user);
    }

    public function emailChangeReverted(Events\EmailChangeReverted $event): void
    {
        $this->log->record('email_change_reverted', $event->user);
    }

    public function passwordChanged(Events\PasswordChanged $event): void
    {
        $this->log->record('password_changed', $event->user);
    }

    public function passwordReset(Events\PasswordReset $event): void
    {
        $this->log->record('password_reset', $event->user, meta: ['sign_in_locks_cleared' => true]);
    }

    /**
     * A bypass is never left unlogged: if the entry can't be written this
     * throws, before the protected attributes are touched.
     */
    public function protectionBypassed(Events\ProtectionBypassed $event): void
    {
        $actor = $this->keyring->guard()->user();

        $this->log->recordOrFail('protection_bypassed', $actor instanceof Authenticatable ? $actor : null, meta: ['reason' => $event->reason]);
    }

    public function cloneSuspected(Events\CloneSuspected $event): void
    {
        $this->log->record('clone_suspected', $event->authenticator->user(), $event->authenticator->factor, meta: ['name' => $event->authenticator->name]);
    }

    public function riskAssessed(Events\RiskAssessed $event): void
    {
        $this->log->record('risk_'.$event->action->name(), $event->user, meta: [
            'checkpoint' => $event->checkpoint->value,
            'score' => $event->risk->score,
            'reasons' => $event->risk->reasons(),
        ]);
    }
}
