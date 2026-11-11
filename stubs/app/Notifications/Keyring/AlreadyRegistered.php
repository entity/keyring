<?php

declare(strict_types=1);

namespace App\Notifications\Keyring;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * Sent to an address that already has an account when someone tries to
 * register with it, instead of telling them it's taken. The notifiable is
 * that bare address, not your user.
 */
class AlreadyRegistered extends Notification
{
    /**
     * @param  string|null  $resetUrl  null when the app has no password resets
     */
    public function __construct(
        public string $loginUrl,
        public ?string $resetUrl = null,
    ) {}

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $message = new MailMessage()
            ->subject(__('You already have an account'))
            ->line(__('Someone tried to create an account with this email address. It already has one, so nothing was created or changed.'))
            ->action(__('Sign in'), $this->loginUrl);

        if ($this->resetUrl !== null) {
            $message->line(__('Forgotten your password? [Reset it here](:url).', ['url' => $this->resetUrl]));
        }

        return $message->line(__('If this wasn\'t you, you can ignore this email.'));
    }
}
