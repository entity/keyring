<?php

declare(strict_types=1);

namespace App\Notifications\Keyring;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * The code for signing in with an email code, or for adding one as a sign-in
 * method ($enrolling). Not queued, so it arrives while the user waits.
 */
class VerificationCode extends Notification
{
    public function __construct(
        #[\SensitiveParameter] public string $code,
        public int $minutes,
        public bool $enrolling = false,
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
            ->line(__('It expires in :minutes minutes.', ['minutes' => $this->minutes]))
            ->line($this->enrolling
                ? __('If you didn\'t ask to add this email as a sign-in method, someone may be signed in to your account. Please change your password.')
                : __('If you didn\'t try to sign in, someone may know your password. Please change it.'));
    }
}
