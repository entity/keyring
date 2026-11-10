<?php

namespace Keyring\Notifications;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Events\Dispatcher;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Str;
use Keyring\Events;
use Keyring\KeyringManager;

/**
 * Sends the app's notification for each security notice it has registered
 * with Keyring::notifications(). One with none registered isn't sent.
 */
class SendSecurityNotifications
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

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
        $this->send($event->user, 'new_device', ['url' => $event->revokeUrl()]);
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
        if ($event->attempt !== null && $event->afterPassword()) {
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
     * there's nothing to tell it otherwise. That address may be whoever took
     * the account, so its copy leaves out the owner's device and IP.
     */
    public function emailChangeReverted(Events\EmailChangeReverted $event): void
    {
        $this->send($event->user, 'email_change_reverted');

        if ($event->change->applied_at !== null) {
            $this->send(Notification::route('mail', $event->change->value), 'email_change_reverted', describeRequest: false);
        }
    }

    /**
     * @param  array<string, string|int>  $with  what this notice has beyond when, device and IP
     */
    protected function send(Authenticatable|AnonymousNotifiable $user, string $type, array $with = [], bool $describeRequest = true): void
    {
        // A model without Notifiable (say, staff that sign in through
        // another guard) has nowhere to send it, so it's skipped rather than
        // failing the request or the queued job.
        if (! method_exists($user, 'routeNotificationFor')) {
            return;
        }

        // The current request, not one captured at boot (Octane).
        $request = request();

        $notification = $this->keyring->notification($type, [
            'when' => now()->toDayDateTimeString(),
            'at' => now(),
            ...$describeRequest ? ['device' => $this->clean($this->keyring->describeDevice($request->userAgent())), 'ip' => $this->keyring->recordedIp($request)] : [],
            ...array_map(fn (mixed $value) => is_string($value) ? $this->clean($value) : $value, $with),
        ]);

        if ($notification !== null) {
            Notification::send($user, $notification);
        }
    }

    /**
     * One capped line, whatever the app does with it: a key's name and a
     * user agent are whatever was sent.
     */
    protected function clean(?string $value): ?string
    {
        return $value === null ? null : Str::squish(Str::limit(mb_scrub($value), 500));
    }
}
