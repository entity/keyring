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
 * with a blank ID and no replacedBy, and the handle stands in for it: the
 * same handle Sessions::handle() gives and Sessions::find() takes.
 */
class SessionResumed
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
