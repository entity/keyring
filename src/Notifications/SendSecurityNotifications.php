<?php

declare(strict_types=1);

namespace Keyring\Notifications;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Events\Dispatcher;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Keyring\Events;
use Keyring\KeyringManager;
use Keyring\Login\Verification;
use Keyring\Support\Throttle;
use Keyring\Support\Url;

/**
 * Sends the notification for each security notice: Keyring's own, or the
 * app's from Keyring::notifications(). One the app turned off isn't sent.
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
            Events\RecoveryCodesGenerated::class => 'recoveryCodesGenerated',
            Events\RiskAssessed::class => 'riskAssessed',
            Events\CloneSuspected::class => 'cloneSuspected',
            Events\AccountLocked::class => 'accountLocked',
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

    /**
     * The reset link went to the account's address, so whoever finished the
     * reset reads that mailbox. It's told even if nobody verified it before.
     */
    public function passwordReset(Events\PasswordReset $event): void
    {
        $this->send($event->user, 'password_changed', addressProven: true);
    }

    public function authenticatorAdded(Events\AuthenticatorAdded $event): void
    {
        $this->send($event->user, 'authenticator_added', ['name' => $event->authenticator->name]);
    }

    public function authenticatorRemoved(Events\AuthenticatorRemoved $event): void
    {
        $this->send($event->user, 'authenticator_removed', ['name' => $event->authenticator->name]);
    }

    /**
     * A later step of a login failed once the first had passed. After the
     * password, the notice says the password was used. After another first
     * step, such as an identity provider, it names that sign-in method
     * instead, and says nothing about the password.
     */
    public function factorFailed(Events\FactorFailed $event): void
    {
        $first = $event->firstFactor();

        if ($event->attempt === null || $first === null) {
            return;
        }

        $user = $event->attempt->user();

        $this->send($user, 'second_factor_failed', $event->afterPassword() ? [] : ['name' => $this->nameOf($user, $first)]);
    }

    public function recoveryCodeUsed(Events\RecoveryCodeUsed $event): void
    {
        $this->send($event->authenticator->user(), 'recovery_code_used', ['remaining' => $event->remaining]);
    }

    /**
     * New codes end the old ones, whether the user asked for them or they
     * came with a sign-in method.
     */
    public function recoveryCodesGenerated(Events\RecoveryCodesGenerated $event): void
    {
        $this->send($event->user, 'recovery_codes_generated');
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
     * The account stays locked until its password is reset, so the notice
     * carries the way to the reset form when the app has one. The device
     * and IP are those of the attempt that locked it.
     */
    public function accountLocked(Events\AccountLocked $event): void
    {
        $this->send($event->user, 'account_locked', Route::has('password.request') ? ['url' => Url::route('password.request')] : []);
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
    protected function send(Authenticatable|AnonymousNotifiable $user, string $type, array $with = [], bool $describeRequest = true, bool $addressProven = false): void
    {
        // A model without Notifiable (say, staff that sign in through
        // another guard) has nowhere to send it, so it's skipped rather than
        // failing the request or the queued job.
        if (! method_exists($user, 'routeNotificationFor')) {
            return;
        }

        // An address nobody has verified may be anyone's: whoever registered
        // typed it. It hears about the account once it's proved to be theirs.
        if (! $addressProven && $user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()) {
            return;
        }

        // A few of each kind, however often the event comes. The security
        // log still has every one.
        // Asked for here, not when the app boots and subscribes this class:
        // the rate limiter's cache store may not be registered by then.
        if (app(Throttle::class)->notifying($type, $this->recipient($user)) !== null) {
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
     * What the user calls the sign-in method a verification was of, such as
     * "Google (taylor@example.com)": the authenticator's name, the one a
     * factor that stores none gives the user, or else the factor's key.
     */
    protected function nameOf(Authenticatable&Model $user, Verification $verification): string
    {
        $keyring = $this->keyring->for($user);

        return ($keyring->find($verification->authenticator) ?? $keyring->of($verification->factor)->first())->name ?? $verification->factor;
    }

    /**
     * Who a notice is counted against: the account, or the bare address.
     */
    protected function recipient(Authenticatable|AnonymousNotifiable $user): string
    {
        return $user instanceof AnonymousNotifiable
            ? 'mail:'.Str::lower((string) ($user->routes['mail'] ?? ''))
            : $user::class.':'.$user->getAuthIdentifier();
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
