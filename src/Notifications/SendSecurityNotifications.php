<?php

namespace Keyring\Notifications;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Events\Dispatcher;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Keyring\Devices\UserAgent;
use Keyring\Events;
use Keyring\Facades\Keyring;

/**
 * Sends the security emails the app has opted into with Keyring::sendSecurityNotices().
 */
class SendSecurityNotifications
{
    /** Every type Keyring::sendSecurityNotices() accepts. */
    public const array TYPES = [
        'new_device', 'password_changed', 'authenticator_added', 'authenticator_removed',
        'second_factor_failed', 'recovery_code_used', 'suspicious_activity', 'clone_suspected',
        'email_changed', 'email_change_reverted',
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
            Events\EmailChanged::class => 'emailChanged',
            Events\EmailChangeReverted::class => 'emailChangeReverted',
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
     * The user now has the new address, and the old one gets its own copy.
     */
    public function emailChanged(Events\EmailChanged $event): void
    {
        $this->send($event->user, 'email_changed');
        $this->send(Notification::route('mail', $event->change->previous_value), 'email_changed');
    }

    /**
     * Only a change that applied ever gave the new address the account, so
     * there's nothing to tell it otherwise.
     */
    public function emailChangeReverted(Events\EmailChangeReverted $event): void
    {
        $this->send($event->user, 'email_change_reverted');

        if ($event->change->applied_at !== null) {
            $this->send(Notification::route('mail', $event->change->value), 'email_change_reverted');
        }
    }

    /**
     * @param  array<string, string|int>  $replace
     */
    protected function send(Authenticatable|AnonymousNotifiable $user, string $type, array $replace = [], ?string $actionUrl = null): void
    {
        // A model without Notifiable (say, staff that sign in through
        // another guard) has nowhere to send it, so it's skipped rather than
        // failing the request or the queued job.
        if (! Keyring::sendsSecurityNotice($type) || ! method_exists($user, 'routeNotificationFor')) {
            return;
        }

        // The current request, not one captured at boot (Octane).
        $request = request();

        $arguments = [
            'type' => $type,
            'details' => [
                'when' => now()->toDayDateTimeString(),
                'device' => UserAgent::describe($request->userAgent()),
                'ip' => $request->ip(),
            ],
            'replace' => $replace,
            'actionUrl' => $actionUrl,
        ];

        // An app's own class may read the user in via() or toMail(), and a
        // bare address hasn't got one, so that copy is always ours, by mail.
        Notification::send($user, $user instanceof AnonymousNotifiable
            ? new SecurityNotice(...$arguments)
            : app(SecurityNotice::class, $arguments));
    }
}
