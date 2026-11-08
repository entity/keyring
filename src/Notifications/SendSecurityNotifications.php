<?php

namespace Keyring\Notifications;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\Notification;
use Keyring\Devices\UserAgent;
use Keyring\Events;
use Keyring\Facades\Keyring;

/**
 * Sends the security emails the app has opted into with Keyring::notify().
 */
class SendSecurityNotifications
{
    /** Every type Keyring::notify() accepts. */
    public const array TYPES = [
        'new_device', 'password_changed', 'authenticator_added', 'authenticator_removed',
        'second_factor_failed', 'recovery_code_used', 'suspicious_activity', 'clone_suspected',
    ];

    /**
     * @return array<class-string, string>
     */
    public function subscribe(Dispatcher $events): array
    {
        return [
            Events\NewDeviceSignedIn::class => 'newDevice',
            Events\PasswordChanged::class => 'passwordChanged',
            Events\PasswordReset::class => 'passwordReset',
            Events\AuthenticatorAdded::class => 'authenticatorAdded',
            Events\AuthenticatorRemoved::class => 'authenticatorRemoved',
            Events\FactorFailed::class => 'factorFailed',
            Events\RecoveryCodeUsed::class => 'recoveryCodeUsed',
            Events\RiskAssessed::class => 'riskAssessed',
            Events\CloneSuspected::class => 'cloneSuspected',
        ];
    }

    public function newDevice(Events\NewDeviceSignedIn $event): void
    {
        $this->send($event->user, 'new_device', actionUrl: $event->revokeUrl());
    }

    public function passwordChanged(Events\PasswordChanged $event): void
    {
        $this->send($event->user, 'password_changed');
    }

    public function passwordReset(Events\PasswordReset $event): void
    {
        $this->send($event->user, 'password_changed');
    }

    public function authenticatorAdded(Events\AuthenticatorAdded $event): void
    {
        $this->send($event->user, 'authenticator_added', ['name' => $event->authenticator->name]);
    }

    public function authenticatorRemoved(Events\AuthenticatorRemoved $event): void
    {
        $this->send($event->user, 'authenticator_removed', ['name' => $event->authenticator->name]);
    }

    public function factorFailed(Events\FactorFailed $event): void
    {
        if ($event->afterPassword()) {
            $this->send($event->attempt->user(), 'second_factor_failed');
        }
    }

    public function recoveryCodeUsed(Events\RecoveryCodeUsed $event): void
    {
        $this->send($event->authenticator->user(), 'recovery_code_used', ['remaining' => $event->remaining]);
    }

    public function riskAssessed(Events\RiskAssessed $event): void
    {
        if ($event->action->notify) {
            $this->send($event->user, 'suspicious_activity', ['reasons' => implode(' ', $event->risk->reasons())]);
        }
    }

    public function cloneSuspected(Events\CloneSuspected $event): void
    {
        $this->send($event->authenticator->user(), 'clone_suspected', ['name' => $event->authenticator->name]);
    }

    /**
     * @param  array<string, string|int>  $replace
     */
    protected function send(Authenticatable $user, string $type, array $replace = [], ?string $actionUrl = null): void
    {
        if (! Keyring::notifies($type)) {
            return;
        }

        // The current request, not one captured at boot (Octane).
        $request = request();

        Notification::send($user, app(SecurityNotice::class, [
            'type' => $type,
            'details' => [
                'when' => now()->toDayDateTimeString(),
                'device' => UserAgent::describe($request->userAgent()),
                'ip' => $request->ip(),
            ],
            'replace' => $replace,
            'actionUrl' => $actionUrl,
        ]));
    }
}
