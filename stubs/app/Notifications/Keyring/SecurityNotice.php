<?php

namespace App\Notifications\Keyring;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueueAfterCommit;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Keyring\Support\MailText;

/**
 * What every security notice shares. Change via() to send them somewhere
 * else, or toMail() to use your own views: here for all of them, or in one
 * notice for just that one.
 *
 * Queued once any open transaction commits, so a change that's rolled back
 * is never announced.
 */
abstract class SecurityNotice extends Notification implements ShouldQueueAfterCommit
{
    use Queueable;

    /**
     * Keyring fills in whichever of these the notice has. Some hold what
     * users and browsers sent (a key's name, a user agent), cut to one line,
     * so escape them for wherever you show them.
     */
    public function __construct(
        public string $when,
        public ?string $device = null,
        public ?string $ip = null,
        public ?string $name = null,
        public ?int $remaining = null,
        public ?string $reasons = null,
        public ?string $url = null,
    ) {}

    abstract protected function subject(): string;

    abstract protected function intro(): string;

    /**
     * The label of the button to $url, for notices that have one.
     */
    protected function action(): ?string
    {
        return null;
    }

    /**
     * The notifiable is a bare address, not your user, for the copies of an
     * email change sent to the address the account no longer has.
     *
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * Mail lines are read as Markdown, so anything that could hold a user's
     * text goes through MailText::plain() to stay plain text.
     */
    public function toMail(object $notifiable): MailMessage
    {
        $message = new MailMessage()->subject($this->subject())->line(MailText::plain($this->intro()));

        $details = array_filter([__('When') => $this->when, __('Device') => $this->device, __('IP address') => $this->ip]);

        foreach ($details as $label => $value) {
            $message->line(MailText::plain("{$label}: {$value}"));
        }

        if ($this->url !== null && $this->action() !== null) {
            $message->action($this->action(), $this->url);
        }

        return $message->line(__('If this wasn\'t you, change your password and check your sign-in methods straight away.'));
    }
}
