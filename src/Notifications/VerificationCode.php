<?php

namespace Keyring\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * Sent right away (not queued) so the code arrives while the user waits.
 */
class VerificationCode extends Notification
{
    public function __construct(
        #[\SensitiveParameter] public readonly string $code,
        public readonly int $ttl,
        public readonly bool $enrolling = false,
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
        return new MailMessage()
            ->subject(__('Your verification code'))
            ->line(__('Your verification code is:'))
            ->line('**'.trim(chunk_split($this->code, 4, ' ')).'**')
            ->line(__('It expires in :minutes minutes.', ['minutes' => intdiv($this->ttl, 60)]))
            ->line($this->enrolling
                ? __('If you didn\'t ask to add this email as a sign-in method, someone may be signed in to your account. Please change your password.')
                : __('If you didn\'t try to sign in, someone may know your password. Please change it.'));
    }
}
