<?php

declare(strict_types=1);

namespace App\Notifications\Keyring;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Keyring\Support\MailText;

/**
 * The code for signing in with an email code, or for adding one as a sign-in
 * method ($enrolling). Not queued, so it arrives while the user waits.
 * $contact is "support_contact" from config/keyring.php: a URL or an address.
 */
class VerificationCode extends Notification
{
    public function __construct(
        #[\SensitiveParameter] public string $code,
        public int $minutes,
        public bool $enrolling = false,
        public ?string $contact = null,
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
            ->subject(__('Your verification code'))
            ->line(__('Your verification code is:'))
            ->line('**'.trim(chunk_split($this->code, 4, ' ')).'**')
            ->line(__('It expires in :minutes minutes.', ['minutes' => $this->minutes]))
            ->line($this->enrolling
                ? __('If you didn\'t ask to add this email as a sign-in method, someone may be signed in to your account. Please change your password.')
                : __('If you didn\'t try to sign in, someone may know your password. Please change it.'));

        return $this->contact === null
            ? $message
            : $message->line(MailText::contact(__('If this wasn\'t you and you need help, contact us:'), $this->contact));
    }
}
