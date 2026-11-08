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
            ->subject(__('keyring::notifications.email_change_notice.subject'))
            ->line(__('keyring::notifications.email_change_notice.intro', ['email' => $this->masked()]));

        if ($this->confirmToken !== null) {
            $message->line(__('keyring::notifications.email_change_notice.confirm'))
                ->action(__('keyring::notifications.email_change_notice.action'), Url::route('keyring.email.confirm', ['change' => $this->change->id, 'token' => $this->confirmToken]));
        }

        return $message
            ->line(__('keyring::notifications.email_change_notice.revert'))
            ->line(Url::route('keyring.email.revert', ['change' => $this->change->id, 'token' => $this->revertToken]));
    }

    protected function masked(): string
    {
        [$local, $domain] = array_pad(explode('@', $this->change->value, 2), 2, '');

        return mb_substr($local, 0, 1).'•••@'.$domain;
    }
}
