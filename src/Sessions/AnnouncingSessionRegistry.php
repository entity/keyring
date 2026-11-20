<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\EveryoneSignedOut;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Support\KeyedHash;
use Throwable;

/**
 * Wraps the configured registry driver, and announces every session that
 * ends through it: a RegisteredSessionEnded for each record revoke(),
 * revokeAll() and revokeDevice() say they revoked, and EveryoneSignedOut
 * for revokeEveryone(). What's announced is what the driver returned, so
 * a record is announced once, by the call that revoked it.
 *
 * A record that was replaced is left out: its session carried on on the
 * record that replaced it, and is announced when that one ends. Moving a
 * session (replace) ends nothing, and neither does prune(), which only
 * forgets what has ended already.
 *
 * Why a session ended is whatever the code around the call said, with
 * because(). Without that, it's plain "revoked".
 *
 * A listener that throws is reported, and stops neither the rest of the
 * announcements nor whatever was revoking. On the database driver, inside
 * a transaction on the registry's connection, the announcements wait for
 * that transaction to commit, and go with it if it's rolled back, as the
 * revocations do. Anywhere else they go out straight away.
 */
class AnnouncingSessionRegistry implements SessionRegistry
{
    protected ?SessionEndReason $reason = null;

    public function __construct(
        protected SessionRegistry $registry,
    ) {}

    /**
     * The driver underneath.
     */
    public function inner(): SessionRegistry
    {
        return $this->registry;
    }

    /**
     * Run the callback with every session it ends announced for this
     * reason. The innermost reason wins, and the one before it is back once
     * the callback returns or throws, so none is left over for the next
     * request or job.
     *
     * @template TResult
     *
     * @param  Closure(): TResult  $callback
     * @return TResult
     */
    public function because(SessionEndReason $reason, Closure $callback): mixed
    {
        $previous = $this->reason;
        $this->reason = $reason;

        try {
            return $callback();
        } finally {
            $this->reason = $previous;
        }
    }

    /**
     * The reason a session ended now would be announced with.
     */
    public function reason(): SessionEndReason
    {
        return $this->reason ?? SessionEndReason::Revoked;
    }

    public function save(RegisteredSession $session): void
    {
        $this->registry->save($session);
    }

    public function find(string $id): ?RegisteredSession
    {
        return $this->registry->find($id);
    }

    public function forUser(Authenticatable $user): Collection
    {
        return $this->registry->forUser($user);
    }

    public function update(string $id, array $changes): void
    {
        $this->registry->update($id, $changes);
    }

    public function revoke(string $id): ?RegisteredSession
    {
        $session = $this->registry->revoke($id);

        $this->ended($session === null ? [] : [$session]);

        return $session;
    }

    public function replace(string $id, RegisteredSession $successor, bool $revoke = false): bool
    {
        return $this->registry->replace($id, $successor, $revoke);
    }

    public function revokeAll(Authenticatable $user, ?string $except = null): Collection
    {
        return tap($this->registry->revokeAll($user, $except), fn (Collection $revoked) => $this->ended($revoked));
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return tap($this->registry->revokeDevice($user, $deviceId), fn (Collection $revoked) => $this->ended($revoked));
    }

    /**
     * The moment is taken once the driver is done, so it covers every
     * session the driver revoked, and perhaps one that signed in as it
     * finished: one ended too many is an extra sign-out somewhere, one too
     * few a session left open.
     */
    public function revokeEveryone(): void
    {
        $this->registry->revokeEveryone();

        $event = new EveryoneSignedOut(now()->getTimestamp());

        $this->whenDurable(fn () => $this->dispatch($event));
    }

    public function prune(): int
    {
        return $this->registry->prune();
    }

    /**
     * Announce the records a call revoked, once the revocation holds. The
     * events are made now, with the reason in force now.
     *
     * @param  iterable<RegisteredSession>  $sessions
     */
    protected function ended(iterable $sessions): void
    {
        $reason = $this->reason();
        $ended = [];

        foreach ($sessions as $session) {
            if ($session->replacedBy !== null) {
                continue;
            }

            try {
                $ended[] = [$session, $this->event($session, $reason)];
            } catch (Throwable $e) {
                report($e);
            }
        }

        if ($ended !== []) {
            $this->whenDurable(function () use ($ended) {
                foreach ($ended as [$session, $event]) {
                    $this->announce($session, $event);
                }
            });
        }
    }

    protected function event(RegisteredSession $session, SessionEndReason $reason): RegisteredSessionEnded
    {
        // As Sessions::handles() has them.
        $handles = KeyedHash::candidates(KeyedHash::SESSION_HANDLES, $session->origin());

        return new RegisteredSessionEnded(
            handle: $handles[0],
            handles: $handles,
            userId: $session->userId,
            userType: $session->userType,
            guard: $session->guard,
            deviceId: $session->deviceId,
            endedAt: $session->revokedAt ?? now()->getTimestamp(),
            reason: $reason,
        );
    }

    /**
     * Announce one record that ended. Every announcement goes through here,
     * so this is where a record would be noted as announced.
     */
    protected function announce(RegisteredSession $session, RegisteredSessionEnded $event): void
    {
        $this->dispatch($event);
    }

    protected function dispatch(object $event): void
    {
        try {
            event($event);
        } catch (Throwable $e) {
            report($e);
        }
    }

    /**
     * Run the callback once what the driver just did holds: after the
     * transaction open on the registry's own connection commits, never if
     * it's rolled back, and straight away when none is open or the driver
     * isn't the database one.
     *
     * Not Laravel's afterCommit(), on the connection or on events: those
     * wait for the latest transaction on any connection, so a rollback
     * elsewhere would lose an announcement for a revocation that stayed.
     *
     * @param  Closure(): void  $callback
     */
    protected function whenDurable(Closure $callback): void
    {
        $transaction = $this->transaction();

        $transaction === null ? $callback() : $transaction->addCallback($callback);
    }

    /**
     * The innermost transaction open on the registry's connection, if the
     * driver is the database one. One a test wraps itself in doesn't count,
     * as it doesn't for Laravel's own callbacks.
     */
    protected function transaction(): ?DatabaseTransactionRecord
    {
        $connection = $this->registry instanceof DatabaseSessionRegistry ? $this->registry->connection() : null;
        $transactions = app()->bound('db.transactions') ? app('db.transactions') : null;

        if (! $connection instanceof Connection || $connection->transactionLevel() === 0 || ! $transactions instanceof DatabaseTransactionsManager) {
            return null;
        }

        return $transactions->callbackApplicableTransactions()->last(fn (DatabaseTransactionRecord $transaction) => $transaction->connection === $connection->getName());
    }
}
