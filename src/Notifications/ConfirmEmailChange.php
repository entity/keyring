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
            ->subject(__('Confirm your new email address'))
            ->line(__('Please confirm this is the new email address for your account.'))
            ->action(__('Confirm email address'), Url::route('keyring.email.confirm', ['change' => $this->change->id, 'token' => $this->token]))
            ->line(__('This link expires :when.', ['when' => $this->change->expires_at->diffForHumans()]))
            ->line(__('If you didn\'t ask for this, you can ignore this email.'));
    }
}
