<?php

namespace Keyring\Risk;

use Keyring\Support\Duration;

/**
 * What to do about a risk. Build with the static helpers and chain extras:
 *
 *     Action::stepUp()->notify()
 *     Action::deny()->revokeAllSessions()->lockFor('1h')->notify()
 *     Action::stepUp()->requirePasswordChange()
 */
final readonly class Action
{
    public function __construct(
        public bool $stepUp = false,
        public bool $reauthenticate = false,
        public bool $deny = false,
        public bool $revokeSessions = false,
        public ?int $lockSeconds = null,
        public bool $notify = false,
        public bool $changePassword = false,
    ) {}

    public static function allow(): self
    {
        return new self;
    }

    /**
     * At login: ask for another factor when the user has one.
     * On requests: ask for a fresh verification before sensitive routes.
     */
    public static function stepUp(): self
    {
        return new self(stepUp: true);
    }

    /**
     * On requests: sign the session out so the user signs in again.
     */
    public static function reauthenticate(): self
    {
        return new self(reauthenticate: true);
    }

    /**
     * Refuse the login (with the usual generic error) or end the session.
     */
    public static function deny(): self
    {
        return new self(deny: true, reauthenticate: true);
    }

    #[\NoDiscard]
    public function revokeAllSessions(): self
    {
        return clone ($this, ['revokeSessions' => true]);
    }

    #[\NoDiscard]
    public function withoutRevokingSessions(): self
    {
        return clone ($this, ['revokeSessions' => false]);
    }

    #[\NoDiscard]
    public function lockFor(string|int $duration): self
    {
        return clone ($this, ['lockSeconds' => Duration::seconds($duration)]);
    }

    #[\NoDiscard]
    public function notify(): self
    {
        return clone ($this, ['notify' => true]);
    }

    /**
     * Hold the user until they choose a new password: for a signal that
     * says theirs is known to someone else, like BreachedPassword. They
     * can still sign in, and are sent to keyring.password_change_url from
     * every page until it's done.
     */
    #[\NoDiscard]
    public function requirePasswordChange(): self
    {
        return clone ($this, ['changePassword' => true]);
    }

    public function doesSomething(): bool
    {
        return $this->stepUp || $this->reauthenticate || $this->deny || $this->revokeSessions || $this->lockSeconds !== null || $this->notify || $this->changePassword;
    }

    /**
     * A short name for logs: the strongest part of the action.
     */
    public function name(): string
    {
        return match (true) {
            $this->deny => 'denied',
            $this->reauthenticate => 'reauthenticate',
            $this->lockSeconds !== null => 'locked',
            $this->changePassword => 'password_change',
            $this->stepUp => 'step_up',
            $this->revokeSessions => 'revoked_sessions',
            $this->notify => 'notified',
            default => 'allowed',
        };
    }
}
