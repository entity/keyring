<?php

namespace Keyring\Notifications;

use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Keyring\Models\PendingChange;
use Keyring\Support\Url;

/**
 * Sent to the current address: your email is being changed. Accounts without
 * a second factor must also confirm from here.
 */
class EmailChangeNotice extends Notification
{
    public function __construct(
        public readonly PendingChange $change,
        #[\SensitiveParameter] public readonly string $revertToken,
        #[\SensitiveParameter] public readonly ?string $confirmToken = null,
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $message = new MailMessage()
            ->subject(__('Your email address is being changed'))
            ->line(__('Someone asked to change the email address on your account to :email.', ['email' => $this->masked()]));

        if ($this->confirmToken !== null) {
            $message->line(__('To finish the change, confirm it from this address too.'))
                ->action(__('Confirm the change'), Url::route('keyring.email.confirm', ['change' => $this->change->id, 'token' => $this->confirmToken]));
        }

        return $message
            ->line(__('Wasn\'t you? This link cancels the change and signs you out everywhere:'))
            ->line(Url::route('keyring.email.revert', ['change' => $this->change->id, 'token' => $this->revertToken]));
    }

    protected function masked(): string
    {
        [$local, $domain] = array_pad(explode('@', $this->change->value, 2), 2, '');

        return mb_substr($local, 0, 1).'•••@'.$domain;
    }
}
