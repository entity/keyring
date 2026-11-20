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
use Keyring\Contracts\SweepsSessions;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\EveryoneSignedOut;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Exceptions\PartialRevocation;
use Keyring\Support\KeyedHash;
use RuntimeException;
use Throwable;

/**
 * Wraps the configured registry driver, and announces every session that
 * ends through it: a RegisteredSessionEnded for each record revoke(),
 * revokeAll() and revokeDevice() say they revoked, and EveryoneSignedOut
 * for revokeEveryone(). What's announced is what the driver returned, so
 * a record is announced once, by the call that revoked it. A driver that
 * fails part way says what it revoked first with a PartialRevocation:
 * those are announced, and the failure is thrown on.
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
    /**
     * The reason in force, for the whole process: whatever wraps this
     * registry, or however many of these there are, a reason given around
     * the call reaches the one that announces.
     */
    protected static ?SessionEndReason $reason = null;

    /** Whether the driver's store can be swept, once asked. */
    protected ?bool $sweepable = null;

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
    public static function because(SessionEndReason $reason, Closure $callback): mixed
    {
        $previous = static::$reason;
        static::$reason = $reason;

        try {
            return $callback();
        } finally {
            static::$reason = $previous;
        }
    }

    /**
     * The reason a session ended now would be announced with.
     */
    public static function reason(): SessionEndReason
    {
        return static::$reason ?? SessionEndReason::Revoked;
    }

    public function save(#[\SensitiveParameter] RegisteredSession $session): void
    {
        $this->registry->save($session);
    }

    public function find(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        return $this->registry->find($id);
    }

    public function forUser(Authenticatable $user): Collection
    {
        return $this->registry->forUser($user);
    }

    public function update(#[\SensitiveParameter] string $id, array $changes): void
    {
        $this->registry->update($id, $changes);
    }

    public function revoke(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        $session = $this->registry->revoke($id);

        $this->ended($session === null ? [] : [$session]);

        return $session;
    }

    public function replace(#[\SensitiveParameter] string $id, #[\SensitiveParameter] RegisteredSession $successor, bool $revoke = false): bool
    {
        return $this->registry->replace($id, $successor, $revoke);
    }

    public function revokeAll(Authenticatable $user, #[\SensitiveParameter] ?string $except = null): Collection
    {
        return $this->revokeMany(fn () => $this->registry->revokeAll($user, $except));
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return $this->revokeMany(fn () => $this->registry->revokeDevice($user, $deviceId));
    }

    /**
     * The moment is taken once the driver is done, so it covers every
     * session the driver revoked, and perhaps one that signed in as it
     * finished: one ended too many is an extra sign-out somewhere, one too
     * few a session left open. So it's announced when the driver fails
     * part way too, as the database driver can after some of its rounds.
     */
    public function revokeEveryone(): void
    {
        try {
            $this->registry->revokeEveryone();
        } finally {
            $event = new EveryoneSignedOut(now()->getTimestamp());

            $this->whenDurable(function () use ($event): void {
                $this->dispatch($event);
            });
        }
    }

    public function prune(): int
    {
        return $this->registry->prune();
    }

    /**
     * Announce what a bulk revocation revoked, including when it failed
     * part way. Then the failure itself is thrown on.
     *
     * @param  Closure(): Collection<int, RegisteredSession>  $revoke
     * @return Collection<int, RegisteredSession>
     */
    protected function revokeMany(Closure $revoke): Collection
    {
        try {
            $revoked = $revoke();
        } catch (PartialRevocation $e) {
            $this->ended($e->revoked);

            throw $e->getPrevious() ?? $e;
        }

        $this->ended($revoked);

        return $revoked;
    }

    /**
     * The driver's sweeping, if it can (SweepsSessions).
     */
    public function sweeper(): ?SweepsSessions
    {
        return $this->registry instanceof SweepsSessions ? $this->registry : null;
    }

    /**
     * End up to $limit sessions that have timed out with no request to end
     * them, and announce each, then announce again up to what's left of
     * $limit whose announcement was lost. Null when the driver can't sweep.
     * Those revoked in the last few minutes (Sweep::GRACE) may still be
     * being announced, and are left for the next run. Those revoked over a
     * day ago (Sweep::GIVE_UP_AFTER) are given up on.
     */
    public function sweep(int $limit, ?int $idle, ?int $rememberedIdle): ?SweepResult
    {
        if (($sweeper = $this->sweeper()) === null) {
            return null;
        }

        $now = now()->getTimestamp();

        $ended = $sweeper->sweep($now, $idle, $rememberedIdle, $limit);
        $this->announceAll($ended, keepReasons: false);

        $left = $limit - $ended->count();
        $again = $left > 0 ? $sweeper->unannounced($now - Sweep::GIVE_UP_AFTER, $now - Sweep::GRACE, $left) : new Collection;
        $this->announceAll($again, keepReasons: false);

        return new SweepResult(
            ended: $ended->count(),
            announcedAgain: $again->count(),
            more: $ended->count() === $limit || ($left > 0 && $again->count() === $left) || $sweeper->timedOut($now, $idle, $rememberedIdle),
        );
    }

    /**
     * Announce the records a call revoked, once the revocation holds. The
     * events are made now, with the reason in force now.
     *
     * @param  iterable<RegisteredSession>  $sessions
     */
    protected function ended(#[\SensitiveParameter] iterable $sessions): void
    {
        $reason = static::reason();

        $this->announceAll(
            collect($sessions)->reject(fn (RegisteredSession $session) => $session->replacedBy !== null)->map(fn (RegisteredSession $session) => new EndedSession($session, $reason))->values(),
            keepReasons: true,
        );
    }

    /**
     * Make each record's event now, keep why it ended (for announcing it
     * again, should this announcement be lost), then announce them once
     * the revocation holds, and note which went out.
     *
     * @param  Collection<int, EndedSession>  $ended
     */
    protected function announceAll(#[\SensitiveParameter] Collection $ended, bool $keepReasons): void
    {
        if ($ended->isEmpty()) {
            return;
        }

        $events = [];
        $failed = [];

        foreach ($ended as $one) {
            try {
                $events[] = [$one->session, $this->event($one->session, $one->reason)];
            } catch (Throwable $e) {
                $this->report($e);
                $failed[] = $one->session->id;
            }
        }

        if ($keepReasons) {
            foreach (SessionEndReason::cases() as $reason) {
                $ids = $ended->filter(fn (EndedSession $one) => $one->reason === $reason)->map(fn (EndedSession $one) => $one->session->id)->values()->all();

                if ($ids !== []) {
                    $this->keep(fn (SweepsSessions $sweeper) => $sweeper->endedBecause($ids, $reason));
                }
            }
        }

        $this->whenDurable(function () use ($events, $failed) {
            $announced = [];

            foreach ($events as [$session, $event]) {
                $this->announce($session, $event) ? $announced[] = $session->id : $failed[] = $session->id;
            }

            $this->noteAnnounced($announced, $failed);
        });
    }

    protected function event(#[\SensitiveParameter] RegisteredSession $session, SessionEndReason $reason): RegisteredSessionEnded
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
     * Announce one record that ended. Returns whether every listener took
     * it: one that threw was reported, and the record is tried again.
     */
    protected function announce(#[\SensitiveParameter] RegisteredSession $session, RegisteredSessionEnded $event): bool
    {
        return $this->dispatch($event);
    }

    /**
     * Note which records were announced, once each was dispatched, with one
     * write for the lot. The sweep announces again any left out, and those
     * a listener failed for, up to Sweep::ATTEMPTS times. Only on a driver
     * that keeps track (SweepsSessions), and only once its migration has
     * run: until then, nothing is noted, and nothing else changes.
     *
     * @param  list<string>  $announced
     * @param  list<string>  $failed
     */
    protected function noteAnnounced(#[\SensitiveParameter] array $announced, #[\SensitiveParameter] array $failed): void
    {
        $this->keep(fn (SweepsSessions $sweeper) => $sweeper->announced($announced, $failed, now()->getTimestamp(), Sweep::ATTEMPTS));
    }

    /**
     * Write down what the sweep will need, if the driver keeps it. A write
     * that fails is reported, and changes nothing else: no revocation or
     * announcement waits on it.
     *
     * @param  Closure(SweepsSessions): void  $write
     */
    protected function keep(Closure $write): void
    {
        try {
            if (($sweeper = $this->sweeper()) !== null && $this->sweepable($sweeper)) {
                $write($sweeper);
            }
        } catch (Throwable $e) {
            $this->report($e);
        }
    }

    /**
     * Whether the driver's store has what sweeping needs, asked once. One
     * still waiting for its migration is reported the once.
     */
    protected function sweepable(SweepsSessions $sweeper): bool
    {
        if ($this->sweepable !== null) {
            return $this->sweepable;
        }

        if (! $sweepable = $sweeper->canSweep()) {
            $this->report(new RuntimeException('The session registry can\'t note which ended sessions were announced: publish and run Keyring\'s migrations (php artisan keyring:install, then php artisan migrate).'));
        }

        return $this->sweepable = $sweepable;
    }

    protected function dispatch(object $event): bool
    {
        try {
            event($event);

            return true;
        } catch (Throwable $e) {
            $this->report($e);

            return false;
        }
    }

    /**
     * Report a failure, and nothing more: an exception handler that fails
     * too can't stop a sign-out, or the announcements after this one.
     */
    protected function report(Throwable $e): void
    {
        try {
            report($e);
        } catch (Throwable) {
            // Nowhere left to say so.
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
     * as it doesn't for Laravel's own callbacks. A connection split into
     * read and write is one connection, with its transactions on the write
     * side, so that's the one followed.
     *
     * Should finding it fail (Laravel's transaction manager changed, say),
     * the revocation has already been made, so it's announced straight
     * away rather than not at all.
     */
    protected function transaction(): ?DatabaseTransactionRecord
    {
        try {
            $connection = $this->registry instanceof DatabaseSessionRegistry ? $this->registry->connection() : null;
            $transactions = app()->bound('db.transactions') ? app('db.transactions') : null;

            if (! $connection instanceof Connection || $connection->transactionLevel() === 0 || ! $transactions instanceof DatabaseTransactionsManager) {
                return null;
            }

            $transaction = $transactions->callbackApplicableTransactions()->last(fn (DatabaseTransactionRecord $transaction) => $transaction->connection === $connection->getName());

            return $transaction instanceof DatabaseTransactionRecord ? $transaction : null;
        } catch (Throwable $e) {
            $this->report($e);

            return null;
        }
    }
}
