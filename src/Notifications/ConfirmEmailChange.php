<?php

namespace Keyring\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Keyring\Models\PendingChange;
use Keyring\Support\Url;

/**
 * Sent to the new address: confirm it's yours.
 */
class ConfirmEmailChange extends Notification
{
    public function __construct(
        public readonly PendingChange $change,
        #[\SensitiveParameter] public readonly string $token,
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return new MailMessage()
            ->subject(__('keyring::notifications.confirm_email_change.subject'))
            ->line(__('keyring::notifications.confirm_email_change.intro'))
            ->action(__('keyring::notifications.confirm_email_change.action'), Url::route('keyring.email.confirm', ['change' => $this->change->id, 'token' => $this->token]))
            ->line(__('keyring::notifications.confirm_email_change.expires', ['when' => $this->change->expires_at->diffForHumans()]))
            ->line(__('keyring::notifications.confirm_email_change.outro'));
    }
}
