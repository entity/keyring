<?php

namespace App\Notifications\Keyring;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Keyring\Support\MailText;

/**
 * Sent to the current address during an email change: your email is being
 * changed, with a link to cancel it. Accounts without a second factor must
 * also confirm from here, and get $confirmUrl. The notifiable is that bare
 * address, not your user.
 */
class EmailChangeNotice extends Notification
{
    /**
     * @param  string  $email  the new address, with most of its name hidden
     */
    public function __construct(
        public string $email,
        #[\SensitiveParameter] public string $revertUrl,
        #[\SensitiveParameter] public ?string $confirmUrl = null,
    ) {}

    /**
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * The address is whatever was typed, so it goes through MailText::plain()
     * to stay plain text in a Markdown mail.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $message = new MailMessage()
            ->subject(__('Your email address is being changed'))
            ->line(MailText::plain(__('Someone asked to change the email address on your account to :email.', ['email' => $this->email])));

        if ($this->confirmUrl !== null) {
            $message->line(__('To finish the change, confirm it from this address too.'))
                ->action(__('Confirm the change'), $this->confirmUrl);
        }

        return $message
            ->line(__('Wasn\'t you? This link cancels the change and signs you out everywhere:'))
            ->line($this->revertUrl);
    }
}
