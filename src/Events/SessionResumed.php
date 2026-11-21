<?php

declare(strict_types=1);

namespace Keyring\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;

/**
 * A "remember me" cookie carried a session on after it had gone unused: the
 * browser is signed in again with nothing proved. The record is the one the
 * session moved to.
 *
 * The record's ID is what the browser's "remember me" cookie now holds, so
 * it stays in this request. Queued, the event keeps the rest of the record
 * without its registry IDs (RegisteredSession::withoutIds()), and the handle
 * stands in for them: the same handle Sessions::handle() gives and
 * Sessions::find() takes.
 */
class SessionResumed
{
    use Dispatchable, SerializesModels {
        SerializesModels::__serialize as protected serializeModels;
    }

    /**
     * The session's handle, worked out from the full record when the event
     * is made, so a queued listener gets the same one.
     */
    public readonly string $handle;

    public function __construct(
        public readonly Authenticatable $user,
        #[\SensitiveParameter] public readonly RegisteredSession $session,
        ?string $handle = null,
    ) {
        $this->handle = $handle ?? app(Sessions::class)->handle($session);
    }

    /**
     * @return array<string, mixed>
     */
    public function __serialize(): array
    {
        return [
            ...$this->serializeModels(),
            'session' => $this->session->withoutIds(),
        ];
    }
}
