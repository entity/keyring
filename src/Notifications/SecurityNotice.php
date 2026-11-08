<?php

namespace Keyring\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueueAfterCommit;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * One notification for every security notice ("new sign in", "password
 * changed", "someone failed your second factor"...). Copy lives in
 * lang/en/notifications.php, keyed by type.
 *
 * Queued once any open transaction commits, so a change that's rolled back
 * is never announced, and the job never reads the user before the change.
 */
class SecurityNotice extends Notification implements ShouldQueueAfterCommit
{
    use Queueable;

    /**
     * @param  array<string, string|int|null>  $details  shown as "Label: value" lines, keyed by keyring::notifications.details
     * @param  array<string, string|int>  $replace  placeholders for the copy
     */
    public function __construct(
        public readonly string $type,
        public readonly array $details = [],
        public readonly array $replace = [],
        public readonly ?string $actionUrl = null,
    ) {}

    /**
     * Email by default. Extend this class to send it elsewhere (Slack, SMS,
     * the database...) and register yours with Keyring::securityNoticesUsing().
     *
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $content = $this->content();

        $message = new MailMessage()->subject($content['subject'])->line($content['intro']);

        foreach ($content['details'] as $label => $value) {
            $message->line($label.': '.$value);
        }

        if ($content['action'] !== null) {
            $message->action($content['action']['text'], $content['action']['url']);
        }

        return $message->line($content['footer']);
    }

    /**
     * For the database and broadcast channels.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return ['type' => $this->type, ...$this->content()];
    }

    /**
     * What the notice says, translated, for any channel: build a Slack or SMS
     * message from this rather than from the raw type.
     *
     * @return array{subject: string, intro: string, details: array<string, string>, action: array{text: string, url: string}|null, footer: string}
     */
    public function content(): array
    {
        $key = 'keyring::notifications.'.$this->type;
        $details = [];

        foreach (array_filter($this->details, fn ($value) => $value !== null && $value !== '') as $label => $value) {
            $details[__('keyring::notifications.details.'.$label)] = (string) $value;
        }

        return [
            'subject' => __($key.'.subject', $this->replace),
            'intro' => __($key.'.intro', $this->replace),
            'details' => $details,
            'action' => $this->actionUrl === null ? null : ['text' => __($key.'.action'), 'url' => $this->actionUrl],
            'footer' => __('keyring::notifications.footer'),
        ];
    }
}
