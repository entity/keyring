<?php

namespace App\Notifications\Keyring;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * Sent to an address that already has an account when someone tries to move
 * another account to it, instead of telling them it's taken. The notifiable
 * is that bare address, not your user.
 */
class EmailAddressInUse extends Notification
{
    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        return new MailMessage()
            ->subject(__('Someone tried to use your email address'))
            ->line(__('Someone tried to change another account\'s email address to this one. This address already has an account, so nothing was changed.'))
            ->line(__('If this was you, sign in to your existing account instead. Otherwise, you can ignore this email.'));
    }
}
