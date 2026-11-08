<?php

namespace Keyring\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Keyring\Support\Url;

class ResetPassword extends Notification
{
    public function __construct(
        #[\SensitiveParameter] public readonly string $token,
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $email = $notifiable->getEmailForPasswordReset();

        return new MailMessage()
            ->subject(__('Reset your password'))
            ->line(__('Someone asked to reset the password for your account.'))
            ->action(__('Reset password'), Url::route('password.reset', ['token' => $this->token, 'email' => $email]))
            ->line(__('This link expires in :count minutes.', ['count' => config('auth.passwords.'.(config('keyring.passwords.broker') ?? config('auth.defaults.passwords')).'.expire', 60)]))
            ->line(__('If you didn\'t ask for this, you can ignore this email. Your password won\'t change.'));
    }
}
