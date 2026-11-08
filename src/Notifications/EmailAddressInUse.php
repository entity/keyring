<?php

namespace Keyring\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * Sent to an address that already has an account when someone tries to move
 * another account to it, instead of telling the requester it's taken.
 */
class EmailAddressInUse extends Notification
{
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return new MailMessage()
            ->subject(__('keyring::notifications.email_address_in_use.subject'))
            ->line(__('keyring::notifications.email_address_in_use.intro'))
            ->line(__('keyring::notifications.email_address_in_use.outro'));
    }
}
