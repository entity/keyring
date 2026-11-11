<?php

namespace Keyring\Concerns;

use Illuminate\Notifications\Notification;
use InvalidArgumentException;
use Keyring\Exceptions\MissingNotification;

/**
 * The app's notification for each email Keyring sends.
 */
trait ManagesNotifications
{
    /**
     * Every notification Keyring can send: the security notices, which are
     * only sent once the app registers one, then the emails a flow needs.
     */
    public const array NOTIFICATIONS = [
        'new_device', 'password_changed', 'authenticator_added', 'authenticator_removed',
        'second_factor_failed', 'recovery_code_used', 'recovery_codes_generated', 'suspicious_activity',
        'clone_suspected', 'account_locked', 'email_changed', 'email_change_reverted',
        'verification_code', 'confirm_email_change', 'email_change_notice', 'email_address_in_use',
        'already_registered',
    ];

    /** @var array<string, class-string<Notification>> The app's notification for each type it sends. */
    protected array $notifications = [];

    /**
     * The app's notification for each type Keyring sends, added to any set
     * before. A security notice with none isn't sent, and null takes one out
     * again. Keyring builds each through the container, passing what it has
     * to say as named constructor arguments.
     *
     * @param  array<string, class-string<Notification>|null>  $notifications
     */
    public function notifications(array $notifications): static
    {
        if ($unknown = array_diff(array_keys($notifications), self::NOTIFICATIONS)) {
            throw new InvalidArgumentException('Unknown notification types: '.implode(', ', $unknown).'. Keyring sends: '.implode(', ', self::NOTIFICATIONS).'.');
        }

        $this->notifications = array_filter([...$this->notifications, ...$notifications]);

        return $this;
    }

    public function hasNotification(string $type): bool
    {
        return isset($this->notifications[$type]);
    }

    /**
     * The app's notification of a type, or null when it hasn't one.
     *
     * @param  array<string, mixed>  $arguments
     */
    public function notification(string $type, array $arguments = []): ?Notification
    {
        return $this->hasNotification($type)
            ? app($this->notifications[$type], $arguments)
            : null;
    }

    /**
     * For the emails a flow can't work without, like the code for an email
     * code: the app's notification, or an exception saying which is missing.
     *
     * @param  array<string, mixed>  $arguments
     */
    public function requiredNotification(string $type, array $arguments = []): Notification
    {
        return $this->notification($type, $arguments) ?? throw MissingNotification::for($type);
    }
}
