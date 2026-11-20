<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\SweepsSessions;
use Keyring\Enums\SessionEndReason;

class DatabaseSessionRegistry implements SessionRegistry, SweepsSessions
{
    /** The columns the sweep needs, from their own migration. */
    public const array SWEEP_COLUMNS = ['announced_at', 'end_reason', 'announce_attempts', 'announce_after'];

    /** How many IDs one statement names: SQLite takes the fewest. */
    protected const int CHUNK = 500;

    /** Whether the sweep's notes are kept, once asked (notes). */
    protected ?bool $notes = null;

    public function __construct(
        protected ConnectionInterface $connection,
        protected string $table = 'keyring_sessions',
    ) {}

    public function save(#[\SensitiveParameter] RegisteredSession $session): void
    {
        // Never clear revoked_at from a stale copy: a revocation that lands
        // between reading and saving a record must stick. So must the
        // record that replaced it.
        $row = $session->toArray();

        // A record a session started on has no origin to write. Leaving the
        // column out keeps signing in working on a table that's still
        // waiting for the migration that adds it.
        if ($row['origin'] === null) {
            unset($row['origin']);
        }

        $this->query()->upsert([$row], ['id'], array_values(array_diff(array_keys($row), ['id', 'revoked_at', 'replaced_by', 'replaced_at'])));
    }

    public function find(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        $row = $this->query()->find($id);

        return $row === null ? null : RegisteredSession::fromArray((array) $row);
    }

    public function forUser(Authenticatable $user): Collection
    {
        return $this->activeFor($user)
            ->where('expires_at', '>', now()->getTimestamp())
            ->latest('last_activity_at')
            ->get()
            ->map(fn (object $row) => RegisteredSession::fromArray((array) $row));
    }

    public function update(#[\SensitiveParameter] string $id, array $changes): void
    {
        $this->query()->where('id', $id)->update(RegisteredSession::columns($changes));
    }

    /**
     * The row is read with a lock and revoked in the same transaction, so
     * nothing changes it in between: of two calls the second waits, then
     * finds it revoked and returns null. A locking read is always made on
     * the write connection, and sees the latest committed row even inside a
     * caller's MySQL transaction that took its snapshot earlier. It can't
     * deadlock with replace() or revokeEveryone(): this takes one lock (the
     * row, or on MySQL the gap where a missing one would be) and nothing
     * after it, so it never holds one while waiting for another.
     */
    public function revoke(#[\SensitiveParameter] string $id): ?RegisteredSession
    {
        return $this->connection->transaction(function () use ($id) {
            $row = $this->query()->lockForUpdate()->find($id);
            $session = $row === null ? null : RegisteredSession::fromArray((array) $row);

            if ($session === null || $session->revokedAt !== null) {
                return null;
            }

            $now = now()->getTimestamp();
            $this->query()->where('id', $id)->update(['revoked_at' => $now, ...$this->reason()]);

            return $session->with(['revokedAt' => $now]);
        });
    }

    /**
     * The update only matches a record still in use, and holds its row until
     * the new record is stored. Of two requests at the same moment the
     * second waits, then matches nothing.
     */
    public function replace(#[\SensitiveParameter] string $id, #[\SensitiveParameter] RegisteredSession $successor, bool $revoke = false): bool
    {
        return $this->connection->transaction(function () use ($id, $successor, $revoke) {
            $now = now()->getTimestamp();

            $replaced = $this->query()->where('id', $id)->whereNull('revoked_at')->whereNull('replaced_by')->update([
                'replaced_by' => $successor->id,
                'replaced_at' => $now,
                ...$revoke ? ['revoked_at' => $now] : [],
            ]) === 1;

            if ($replaced) {
                $this->save($successor);
            }

            return $replaced;
        });
    }

    public function revokeAll(Authenticatable $user, #[\SensitiveParameter] ?string $except = null): Collection
    {
        return $this->revokeFound($this->activeFor($user)->when($except, fn (Builder $query) => $query->where('id', '!=', $except)));
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return $this->revokeFound($this->activeFor($user)->where('device_id', $deviceId));
    }

    /**
     * Find the records with a lock, then revoke them by ID in the same
     * transaction, a thousand at a time as revokeEveryone() does, so a user
     * with years of expired records that were never pruned doesn't make one
     * statement too big. A locking read is always made on the write
     * connection, and reads the latest committed rows, not the snapshot of
     * a caller's MySQL transaction that started earlier: a session signed
     * in since then is found and revoked. It takes the locks the single
     * UPDATE this used to be took (on MySQL, the user's range of the
     * index), so a sign in for this user waits until it's done, and the
     * rows can't change between the read and the update. So the records
     * returned are exactly the ones revoked, and the update matches what
     * the single UPDATE matched. Of two calls at once the second waits, and
     * then finds nothing left to revoke. Rows are read in ID order, so two
     * calls on PostgreSQL lock the rows they share in the same order.
     *
     * @return Collection<int, RegisteredSession>
     */
    protected function revokeFound(Builder $query): Collection
    {
        return $this->connection->transaction(function () use ($query) {
            $now = now()->getTimestamp();

            $found = $query->orderBy('id')->lockForUpdate()->get()->map(fn (object $row) => RegisteredSession::fromArray((array) $row));

            $reason = $this->reason();

            $found->pluck('id')->chunk(self::CHUNK)->each(
                fn (Collection $ids) => $this->query()->whereIn('id', $ids->values())->whereNull('revoked_at')->whereNull('replaced_by')->update(['revoked_at' => $now, ...$reason]),
            );

            return $found->map(fn (RegisteredSession $session) => $session->with(['revokedAt' => $now]));
        });
    }

    /**
     * A thousand at a time, found first and then revoked by ID, until none
     * are left. A session moving to a new record holds its old one until the
     * new one is stored, so the round that comes to the old one waits, and
     * the next finds where it went. Replaced records are revoked with the
     * rest, which is what keeps the rounds coming. Rows are locked one by
     * one this way, never a range, so a sign in or a move isn't held up or
     * deadlocked. A session that started after this did is left alone, so
     * new sign ins can't keep it going. Each round reads from the database
     * it writes to: a replica that lags would keep handing back what the
     * last round revoked.
     */
    public function revokeEveryone(): void
    {
        $now = now()->getTimestamp();

        // EveryoneSignedOut announces them all at once, so the sweep has
        // none of them to announce one by one.
        $announced = $this->notes() ? ['announced_at' => $now, 'end_reason' => SessionEndReason::Revoked->value] : [];

        do {
            $ids = $this->query()
                ->useWritePdo()
                ->whereNull('revoked_at')
                ->where('authenticated_at', '<=', $now)
                ->where('expires_at', '>', $now)
                ->limit(1000)
                ->pluck('id');

            $this->query()->whereIn('id', $ids)->whereNull('revoked_at')->update(['revoked_at' => $now, ...$announced]);
        } while ($ids->isNotEmpty());
    }

    /**
     * Before the migration the sweep needs, every record that has expired or
     * been revoked goes, as it always has. After it, whether or not a sweep
     * is scheduled, a record goes once nothing is left to announce for it:
     * a replaced one when it expires, a revoked one once it's announced or
     * the sweep has given up on it (Sweep::GIVE_UP_AFTER). One that has
     * timed out is left for the sweep to end, until a day past its expiry:
     * with no sweep running, or one that can't keep up, the table can't
     * grow without end.
     */
    public function prune(): int
    {
        $now = now()->getTimestamp();

        if (! $this->canSweep()) {
            return $this->query()
                ->where('expires_at', '<=', $now)
                ->orWhere(fn (Builder $query) => $query->whereNotNull('revoked_at')->whereNull('replaced_by'))
                ->delete();
        }

        return $this->query()
            ->where(fn (Builder $query) => $query->whereNotNull('replaced_by')->where('expires_at', '<=', $now))
            ->orWhere(fn (Builder $query) => $query->whereNotNull('revoked_at')->whereNull('replaced_by')->where(
                fn (Builder $query) => $query->whereNotNull('announced_at')->orWhere('revoked_at', '<=', $now - Sweep::GIVE_UP_AFTER),
            ))
            ->orWhere(fn (Builder $query) => $query->whereNull('revoked_at')->where('expires_at', '<=', $now - Sweep::GIVE_UP_AFTER))
            ->delete();
    }

    public function canSweep(): bool
    {
        return $this->connection instanceof Connection
            && $this->connection->getSchemaBuilder()->hasColumns($this->table, self::SWEEP_COLUMNS);
    }

    /**
     * Whether to keep the notes the sweep reads (why each record ended,
     * whether it was announced). Asked of the database once per process,
     * and once a day across processes while the migration is still to be
     * run: the answer "not yet" is kept in the cache, so a request doesn't
     * pay for a schema query, or log a warning, each time it ends a
     * session. Running the migration forgets it. A process that started
     * before the migration (Octane, a queue worker) keeps not noting until
     * it restarts.
     */
    protected function notes(): bool
    {
        if ($this->notes !== null) {
            return $this->notes;
        }

        $key = self::unmigratedKey($this->connection instanceof Connection ? $this->connection->getName() : null, $this->table);

        if (rescue(fn () => cache()->has($key), false, report: false)) {
            return $this->notes = false;
        }

        if (! $this->notes = $this->canSweep()) {
            rescue(fn () => cache()->put($key, true, Sweep::GIVE_UP_AFTER), report: false);
            rescue(fn () => logger()->warning("The [{$this->table}] table is missing the columns Keyring notes announced sessions in. Sessions end and are announced as usual, but none is announced again if its announcement is lost, and keyring:sweep won't run. Publish and run Keyring's migrations: php artisan keyring:install, then php artisan migrate."), report: false);
        }

        return $this->notes;
    }

    /**
     * Where the cache keeps that a sessions table is still waiting for the
     * migration the sweep needs.
     */
    public static function unmigratedKey(?string $connection, string $table): string
    {
        return 'keyring:sessions:unmigrated:'.sha1(($connection ?? '').'|'.$table);
    }

    /**
     * What a revocation writes besides its time: why, if the notes are kept,
     * so a record whose announcement is lost is announced again for the
     * right reason. It's the reason in force where the call was made
     * (AnnouncingSessionRegistry::because).
     *
     * @return array<string, string>
     */
    protected function reason(): array
    {
        return $this->notes() ? ['end_reason' => AnnouncingSessionRegistry::reason()->value] : [];
    }

    /**
     * The records that have timed out are found oldest first, by the time
     * each timed out, on the write connection: each kind with its own query
     * on its own index. One more than $limit is asked for, to say whether
     * more are left. Then they're locked by ID, in ID order, as revokeAll()
     * locks a user's, so of two sweeps the second waits for the first, and
     * a sweep and a sign-out never take the same rows in a different order.
     * Locking by ID takes the rows alone, not a range of an index a sign-out
     * is writing into. Whether each has timed out is decided again from the
     * locked row, against one $now: one revoked or moved meanwhile is left,
     * and so is one a request used a moment ago. The rest are ended by ID,
     * still only if neither revoked nor replaced, so what's returned is
     * exactly what this call ended. A deadlock is tried again, twice.
     */
    public function sweep(int $now, ?int $idle, ?int $rememberedIdle, int $limit): array
    {
        return $this->connection->transaction(function () use ($now, $idle, $rememberedIdle, $limit) {
            $open = fn () => $this->query()->useWritePdo()->whereNull('revoked_at')->whereNull('replaced_by');

            /** @var array<string, int> $due when each timed out, by ID */
            $due = $open()->where('expires_at', '<=', $now)->oldest('expires_at')->limit($limit + 1)->pluck('expires_at', 'id')->map(fn (mixed $at) => (int) $at)->all();

            foreach ([false => $idle, true => $rememberedIdle] as $remembered => $limitFor) {
                if ($limitFor === null) {
                    continue;
                }

                $open()->where('remembered', (bool) $remembered)->where('last_activity_at', '<', $now - $limitFor)
                    ->oldest('last_activity_at')->limit($limit + 1)->pluck('last_activity_at', 'id')
                    ->each(function (mixed $at, string $id) use (&$due, $limitFor) {
                        $due[$id] = min($due[$id] ?? PHP_INT_MAX, (int) $at + $limitFor + 1);
                    });
            }

            asort($due);
            $ids = array_map(strval(...), array_keys(array_slice($due, 0, $limit, preserve_keys: true)));
            sort($ids);

            $ended = new Collection($ids)->chunk(self::CHUNK)
                ->flatMap(fn (Collection $chunk) => $this->query()->whereIn('id', $chunk->values()->all())->orderBy('id')->lockForUpdate()->get())
                ->map(fn (object $row) => RegisteredSession::fromArray((array) $row))
                ->map(fn (RegisteredSession $session) => match (true) {
                    $session->revokedAt !== null, $session->replacedBy !== null => null,
                    $session->expiresAt <= $now => new EndedSession($session->with(['revokedAt' => $now]), SessionEndReason::Expired),
                    $this->idledOut($session, $now, $idle, $rememberedIdle) => new EndedSession($session->with(['revokedAt' => $now]), SessionEndReason::Idle),
                    default => null,
                })
                ->filter()
                ->values();

            foreach ([SessionEndReason::Expired, SessionEndReason::Idle] as $reason) {
                $ended->filter(fn (EndedSession $one) => $one->reason === $reason)->map(fn (EndedSession $one) => $one->session->id)->chunk(self::CHUNK)->each(
                    fn (Collection $chunk) => $this->query()->whereIn('id', $chunk->values()->all())->whereNull('revoked_at')->whereNull('replaced_by')->update(['revoked_at' => $now, 'end_reason' => $reason->value]),
                );
            }

            return ['ended' => $ended, 'more' => count($due) > $limit];
        }, attempts: 3);
    }

    /**
     * Unused for longer than the limit for its kind, as Sessions::idledOut()
     * has it: strictly more seconds than the limit since its last activity.
     */
    protected function idledOut(RegisteredSession $session, int $now, ?int $idle, ?int $rememberedIdle): bool
    {
        $limit = $session->remembered ? $rememberedIdle : $idle;

        return $limit !== null && $now - $session->lastActivityAt > $limit;
    }

    /**
     * Oldest first, one more than $limit to say whether more are left. Ones
     * whose announcement failed wait for their next try (announce_after). A
     * record revoked before this driver kept why has no reason, and is
     * announced again as plain "revoked".
     */
    public function unannounced(int $from, int $until, int $now, int $limit): array
    {
        $found = $this->query()->useWritePdo()
            ->whereNull('announced_at')
            ->where('revoked_at', '>', $from)
            ->where('revoked_at', '<=', $until)
            ->whereNull('replaced_by')
            ->where(fn (Builder $query) => $query->whereNull('announce_after')->orWhere('announce_after', '<=', $now))
            ->oldest('revoked_at')
            ->orderBy('id')
            ->limit($limit + 1)
            ->get();

        return [
            'ended' => $found->take($limit)->map(fn (object $row) => new EndedSession(RegisteredSession::fromArray((array) $row), SessionEndReason::tryFrom((string) $row->end_reason) ?? SessionEndReason::Revoked))->values(),
            'more' => $found->count() > $limit,
        ];
    }

    /**
     * A failure counts against the record, and puts its next try off for
     * longer each time (Sweep::retryAfter), until the sweep gives up on it
     * a day after its revocation. In a transaction of its own, so a failed
     * write leaves the caller's transaction usable.
     */
    public function announced(#[\SensitiveParameter] array $announced, #[\SensitiveParameter] array $failed, int $at): void
    {
        if (! $this->notes()) {
            return;
        }

        $this->connection->transaction(function () use ($announced, $failed, $at) {
            foreach (array_chunk($announced, self::CHUNK) as $chunk) {
                $this->query()->whereIn('id', $chunk)->update(['announced_at' => $at]);
            }

            foreach (array_chunk($failed, self::CHUNK) as $chunk) {
                $this->query()->whereIn('id', $chunk)->pluck('announce_attempts', 'id')
                    ->groupBy(fn (mixed $attempts) => (int) $attempts, preserveKeys: true)
                    ->each(fn (Collection $group, int $attempts) => $this->query()->whereIn('id', $group->keys()->map(strval(...))->all())->update([
                        'announce_attempts' => $attempts + 1,
                        'announce_after' => $at + Sweep::retryAfter($attempts + 1),
                    ]));
            }
        });
    }

    /**
     * The user's sessions that haven't been revoked or replaced.
     */
    protected function activeFor(Authenticatable $user): Builder
    {
        return $this->query()
            ->where('user_type', RegisteredSession::typeOf($user))
            ->where('user_id', (string) $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->whereNull('replaced_by');
    }

    /**
     * The connection the records are kept on, whose transactions decide
     * when a revocation holds (AnnouncingSessionRegistry).
     */
    public function connection(): ConnectionInterface
    {
        return $this->connection;
    }

    protected function query(): Builder
    {
        return $this->connection->table($this->table);
    }
}
