<?php

namespace Keyring\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * One notification for every security email ("new sign in", "password
 * changed", "someone failed your second factor"...). Copy lives in
 * lang/en/notifications.php, keyed by type.
 */
class SecurityNotice extends Notification implements ShouldQueue
{
    use Queueable;

    /**
     * @param  array<string, string|int|null>  $details  shown as "Label: value" lines
     * @param  array<string, string|int>  $replace  placeholders for the copy
     */
    public function __construct(
        public readonly string $type,
        public readonly array $details = [],
        public readonly array $replace = [],
        public readonly ?string $actionUrl = null,
    ) {}

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $key = 'keyring::notifications.'.$this->type;

        $message = new MailMessage()
            ->subject(__($key.'.subject', $this->replace))
            ->line(__($key.'.intro', $this->replace));

        foreach (array_filter($this->details, fn ($value) => $value !== null && $value !== '') as $label => $value) {
            $message->line(__($label).': '.$value);
        }

        if ($this->actionUrl !== null) {
            $message->action(__($key.'.action'), $this->actionUrl);
        }

        return $message->line(__('keyring::notifications.footer'));
    }
}
