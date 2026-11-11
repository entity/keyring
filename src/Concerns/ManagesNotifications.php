<?php

declare(strict_types=1);

namespace Keyring\Concerns;

use Illuminate\Notifications\Notification;
use InvalidArgumentException;
use Keyring\Exceptions\MissingNotification;
use Keyring\Notifications;

/**
 * The notification for each email Keyring sends: its own, or the app's.
 */
trait ManagesNotifications
{
    /**
     * Every notification Keyring can send: the security notices, then the
     * emails a flow needs.
     */
    public const array NOTIFICATIONS = [
        'new_device', 'password_changed', 'authenticator_added', 'authenticator_removed',
        'second_factor_failed', 'recovery_code_used', 'recovery_codes_generated', 'suspicious_activity',
        'clone_suspected', 'account_locked', 'email_changed', 'email_change_reverted',
        'verification_code', 'confirm_email_change', 'email_change_notice', 'email_address_in_use',
        'already_registered',
    ];

    /**
     * Keyring's own notification for each type, sent unless the app gives
     * its own or turns the type off. A suspected clone is the one type that
     * starts off: the app turns it on with Notifications\CloneSuspected.
     */
    protected const array DEFAULT_NOTIFICATIONS = [
        'new_device' => Notifications\NewDevice::class,
        'password_changed' => Notifications\PasswordChanged::class,
        'authenticator_added' => Notifications\AuthenticatorAdded::class,
        'authenticator_removed' => Notifications\AuthenticatorRemoved::class,
        'second_factor_failed' => Notifications\SecondFactorFailed::class,
        'recovery_code_used' => Notifications\RecoveryCodeUsed::class,
        'recovery_codes_generated' => Notifications\RecoveryCodesGenerated::class,
        'suspicious_activity' => Notifications\SuspiciousActivity::class,
        'account_locked' => Notifications\AccountLocked::class,
        'email_changed' => Notifications\EmailChanged::class,
        'email_change_reverted' => Notifications\EmailChangeReverted::class,
        'verification_code' => Notifications\VerificationCode::class,
        'confirm_email_change' => Notifications\ConfirmEmailChange::class,
        'email_change_notice' => Notifications\EmailChangeNotice::class,
        'email_address_in_use' => Notifications\EmailAddressInUse::class,
        'already_registered' => Notifications\AlreadyRegistered::class,
    ];

    /** @var array<string, class-string<Notification>|null> What the app changed: its own notification for a type, or null for one it turned off. */
    protected array $notifications = [];

    /**
     * Change the notification Keyring sends for a type: the app's own class,
     * or null to send none. Types left out keep Keyring's own, and a call
     * adds to the ones before it. Keyring builds each through the container,
     * passing what it has to say as named constructor arguments.
     *
     * @param  array<string, class-string<Notification>|null>  $notifications
     */
    public function notifications(array $notifications): static
    {
        if ($unknown = array_diff(array_keys($notifications), self::NOTIFICATIONS)) {
            throw new InvalidArgumentException('Unknown notification types: '.implode(', ', $unknown).'. Keyring sends: '.implode(', ', self::NOTIFICATIONS).'.');
        }

        $this->notifications = [...$this->notifications, ...$notifications];

        return $this;
    }

    public function hasNotification(string $type): bool
    {
        return $this->notificationClass($type) !== null;
    }

    /**
     * The notification of a type, or null when it's turned off. Each is also
     * handed where to reach the app's support ("support_contact"), as
     * $contact, for the ones that say who to turn to.
     *
     * @param  array<string, mixed>  $arguments
     */
    public function notification(string $type, array $arguments = []): ?Notification
    {
        $class = $this->notificationClass($type);

        return $class === null
            ? null
            : app($class, ['contact' => config('keyring.support_contact'), ...$arguments]);
    }

    /**
     * For the emails a flow can't work without, like the code for an email
     * code: the notification, or an exception saying which was turned off.
     *
     * @param  array<string, mixed>  $arguments
     */
    public function requiredNotification(string $type, array $arguments = []): Notification
    {
        return $this->notification($type, $arguments) ?? throw MissingNotification::for($type);
    }

    /**
     * @return class-string<Notification>|null
     */
    protected function notificationClass(string $type): ?string
    {
        return array_key_exists($type, $this->notifications)
            ? $this->notifications[$type]
            : self::DEFAULT_NOTIFICATIONS[$type] ?? null;
    }
}
