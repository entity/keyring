<?php

namespace Keyring\Activity;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout as LaravelLockout;
use Illuminate\Auth\Events\PasswordReset as LaravelPasswordReset;
use Illuminate\Events\Dispatcher;
use Keyring\Events\FactorFailed;
use Keyring\Events\Lockout;
use Keyring\Events\PasswordReset;

/**
 * Raises Laravel's own auth events next to Keyring's, as Fortify does, so
 * listeners and packages built for them keep working. (Signing in and out
 * already fire Laravel's Login and Logout through the guard.)
 */
class DispatchLaravelEvents
{
    /**
     * @return array<class-string, string>
     */
    public function subscribe(Dispatcher $events): array
    {
        return [
            FactorFailed::class => 'failed',
            Lockout::class => 'lockout',
            PasswordReset::class => 'passwordReset',
        ];
    }

    public function failed(FactorFailed $event): void
    {
        $username = config('keyring.username');
        $user = $event->attempt?->user();

        // Only who it was for, never the password or code that was tried.
        event(new Failed(config('keyring.guard'), $user, [
            $username => $user?->getAttribute($username) ?? $event->request->input($username),
        ]));
    }

    public function lockout(Lockout $event): void
    {
        event(new LaravelLockout($event->request));
    }

    public function passwordReset(PasswordReset $event): void
    {
        event(new LaravelPasswordReset($event->user));
    }
}
