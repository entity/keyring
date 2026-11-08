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
            ->subject(__('keyring::notifications.verification_code.subject'))
            ->line(__('keyring::notifications.verification_code.intro'))
            ->line('**'.trim(chunk_split($this->code, 4, ' ')).'**')
            ->line(__('keyring::notifications.verification_code.expires', ['minutes' => intdiv($this->ttl, 60)]))
            ->line(__('keyring::notifications.verification_code.'.($this->enrolling ? 'outro_enrolling' : 'outro')));
    }
}
