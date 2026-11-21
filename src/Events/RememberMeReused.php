<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;

/**
 * A "remember me" cookie that had already been used, or a session still
 * open from before it was, turned up again. Each cookie works once, so two
 * browsers held the same ones, and the session was ended for both. The
 * record is the one that was ended: its device, address and browser are
 * those of whoever used the cookie first.
 *
 * Registry IDs stay in this request, as they do everywhere else. Queued,
 * the event keeps the rest of the record with a blank ID and no replacedBy,
 * and the handle stands in for it: the same handle Sessions::handle() gives.
 */
class RememberMeReused
{
    use Dispatchable, SerializesModels {
        SerializesModels::__serialize as serializeModels;
    }

    public function __construct(
        public readonly Authenticatable $user,
        #[\SensitiveParameter] public readonly RegisteredSession $session,
        public readonly ?string $handle = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        return [
            ...$this->serializeModels(),
            'session' => $this->session->with(['id' => '', 'replacedBy' => null]),
            'handle' => $this->handle ?? app(Sessions::class)->handle($this->session),
        ];
    }
}
