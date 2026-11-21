<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\EveryoneSignedOut;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Events\SessionEnded;
use Keyring\Models\SecurityEvent;
use Keyring\Sessions\AnnouncingSessionRegistry;
use Keyring\Sessions\CacheSessionRegistry;
use Keyring\Sessions\DatabaseSessionRegistry;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Sessions\Sessions;
use Keyring\Sessions\Sweep;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    // The sweep compares stored times with now(), so the clock only moves
    // when a test moves it.
    $this->freezeSecond();

    $this->user = taylor();
    $this->announced = new Collection;
    Event::listen(fn (RegisteredSessionEnded $event) => $this->announced->push($event));
});

/**
 * A record of the user's, last used $unused seconds ago, ending $expiresIn
 * seconds from now.
 *
 * @param  array<string, mixed>  $changes
 */
function swept(User $user, int $unused = 0, int $expiresIn = 3600, bool $remembered = false, array $changes = []): RegisteredSession
{
    $now = now()->getTimestamp();
    $session = new RegisteredSession(Str::random(40), (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, $now - $unused, $now - $unused, $now + $expiresIn, remembered: $remembered);

    app(SessionRegistry::class)->save($session = $session->with($changes));

    return $session;
}

function sweepRow(string $id): object
{
    return DB::table('keyring_sessions')->where('id', $id)->sole();
}

function handleFor(RegisteredSession $session): string
{
    return app(Sessions::class)->handle($session);
}

/**
 * The handles announced so far, with why.
 *
 * @return array<string, string>
 */
function announcedReasons(): array
{
    return test()->announced->mapWithKeys(fn (RegisteredSessionEnded $event) => [$event->handle => $event->reason->value])->all();
}

describe('ending what timed out', function () {
    it('ends idle and expired sessions with the reason the middleware would give, by their handles', function () {
        $idle = swept($this->user, unused: 7201);
        $expired = swept($this->user, expiresIn: 0);
        $both = swept($this->user, unused: 9000, expiresIn: -5);

        // One that moved: its handle is the record it started on.
        $started = swept($this->user, unused: 7300);
        $moved = $started->with(['id' => Str::random(40), 'origin' => $started->id]);
        app(SessionRegistry::class)->replace($started->id, $moved);

        $this->artisan('keyring:sweep')
            ->expectsOutputToContain('Ended 4 timed-out sessions, and announced 0 ended sessions again.')
            ->assertSuccessful();

        expect(announcedReasons())->toEqual([
            handleFor($idle) => 'idle',
            handleFor($expired) => 'expired',
            handleFor($both) => 'expired',
            handleFor($started) => 'idle',
        ])
            ->and(sweepRow($idle->id)->revoked_at)->toBe(now()->getTimestamp())
            ->and(sweepRow($idle->id)->end_reason)->toBe('idle')
            ->and(sweepRow($idle->id)->announced_at)->toBe(now()->getTimestamp())
            ->and(sweepRow($started->id)->revoked_at)->toBeNull();
    });

    it('leaves a session at the last second the middleware still lets it through', function () {
        $live = swept($this->user, unused: 7200, expiresIn: 1);
        $remembered = swept($this->user, unused: 14 * 86400, remembered: true);
        $idle = swept($this->user, unused: 14 * 86400 + 1, remembered: true);

        expect(app(Sessions::class)->idledOut(app(SessionRegistry::class)->find($live->id)))->toBeFalse();

        $this->artisan('keyring:sweep')->assertSuccessful();

        expect(announcedReasons())->toBe([handleFor($idle) => 'idle'])
            ->and(sweepRow($live->id)->revoked_at)->toBeNull()
            ->and(sweepRow($remembered->id)->revoked_at)->toBeNull();
    });

    it('ends no session for idling when idling has no limit', function () {
        config(['keyring.sessions.idle' => null, 'keyring.sessions.remember_idle' => null]);
        $idle = swept($this->user, unused: 30 * 86400);
        $expired = swept($this->user, expiresIn: -1);

        $this->artisan('keyring:sweep')->assertSuccessful();

        expect(announcedReasons())->toBe([handleFor($expired) => 'expired'])
            ->and(sweepRow($idle->id)->revoked_at)->toBeNull();
    });

    it('leaves what was revoked or moved, and what a request used a moment ago', function () {
        $revoked = swept($this->user, unused: 9000);
        app(SessionRegistry::class)->revoke($revoked->id);
        $replaced = swept($this->user, unused: 9000);
        app(SessionRegistry::class)->replace($replaced->id, $replaced->with(['id' => Str::random(40), 'origin' => $replaced->id, 'lastActivityAt' => now()->getTimestamp()]));
        $this->announced->splice(0);

        $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 0 timed-out sessions')->assertSuccessful();

        expect($this->announced)->toBeEmpty();
    });

    it('ends no more than sweep_limit in one run, and says more are left', function () {
        config(['keyring.sessions.sweep_limit' => 2]);
        collect([1, 2, 3])->each(fn () => swept($this->user, unused: 9000));

        $this->artisan('keyring:sweep')
            ->expectsOutputToContain('Ended 2 timed-out sessions')
            ->expectsOutputToContain('More are left than one run may take (2 of each).')
            ->assertSuccessful();

        $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 1 timed-out sessions')->doesntExpectOutputToContain('More are left')->assertSuccessful();

        expect($this->announced)->toHaveCount(3);
    });

    it('takes the sessions that timed out longest ago first', function () {
        config(['keyring.sessions.sweep_limit' => 2]);
        $newest = swept($this->user, unused: 7300);
        $oldest = swept($this->user, unused: 9000);
        $expired = swept($this->user, expiresIn: -1000);

        $this->artisan('keyring:sweep')->assertSuccessful();

        // The expired one timed out 1000 seconds ago, the oldest idle one 1799.
        expect(announcedReasons())->toEqual([handleFor($oldest) => 'idle', handleFor($expired) => 'expired'])
            ->and(sweepRow($newest->id)->revoked_at)->toBeNull();
    });

    it('takes a session that both expired and idled out once, as expired', function () {
        $both = swept($this->user, unused: 9000, expiresIn: -1);

        $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 1 timed-out sessions')->assertSuccessful();

        expect(announcedReasons())->toBe([handleFor($both) => 'expired']);
    });

    it('ends more than one statement can name in one run', function () {
        config(['keyring.sessions.sweep_limit' => 1200]);
        $then = now()->getTimestamp() - 9000;
        DB::table('keyring_sessions')->insert(collect(range(1, 1201))->map(fn (int $i) => new RegisteredSession(Str::random(40), (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, $then, $then, $then + 86400)->toArray())->map(fn (array $row) => array_diff_key($row, ['origin' => true]))->all());

        $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 1200 timed-out sessions')->expectsOutputToContain('More are left')->assertSuccessful();

        expect(DB::table('keyring_sessions')->whereNull('revoked_at')->count())->toBe(1)
            ->and(DB::table('keyring_sessions')->whereNotNull('announced_at')->count())->toBe(1200);
    });

    it('takes its limit from config only when it is a positive number', function (mixed $limit, int $taken) {
        config(['keyring.sessions.sweep_limit' => $limit]);

        expect(Sweep::limit())->toBe($taken);
    })->with([
        [50, 50],
        [10000, 10000],
        [50000, 10000],
        ['250', 250],
        [' 250 ', 250],
        ['2.5', 1000],
        [0, 1000],
        ['lots', 1000],
        [null, 1000],
    ]);
});

describe('announcing again', function () {
    it('notes each session announced as it ends, with why', function () {
        $session = swept($this->user);

        app(Sessions::class)->because(SessionEndReason::Risk, fn () => app(SessionRegistry::class)->revoke($session->id));

        expect(sweepRow($session->id))->toMatchObject(['end_reason' => 'risk', 'announced_at' => now()->getTimestamp(), 'announce_attempts' => 0]);
    });

    it('notes an announcement only once the transaction it waited for commits', function () {
        $session = swept($this->user);

        DB::transaction(function () use ($session) {
            app(SessionRegistry::class)->revoke($session->id);

            expect(sweepRow($session->id)->announced_at)->toBeNull()
                ->and(sweepRow($session->id)->end_reason)->toBe('revoked');
        });

        expect(sweepRow($session->id)->announced_at)->toBe(now()->getTimestamp());
    });

    it('announces again, with the reason it was kept with, a record whose announcement was lost', function () {
        $lost = swept($this->user);
        $old = swept($this->user);
        $recent = swept($this->user);
        $announced = swept($this->user);
        $given = swept($this->user);
        $now = now()->getTimestamp();

        DB::table('keyring_sessions')->where('id', $lost->id)->update(['revoked_at' => $now - Sweep::GRACE, 'end_reason' => 'password_reset']);
        DB::table('keyring_sessions')->where('id', $old->id)->update(['revoked_at' => $now - Sweep::GRACE - 60]);
        DB::table('keyring_sessions')->where('id', $recent->id)->update(['revoked_at' => $now - Sweep::GRACE + 1]);
        DB::table('keyring_sessions')->where('id', $announced->id)->update(['revoked_at' => $now - 3600, 'announced_at' => $now - 3600]);
        DB::table('keyring_sessions')->where('id', $given->id)->update(['revoked_at' => $now - Sweep::GIVE_UP_AFTER]);

        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 2 ended sessions again')->assertSuccessful();

        expect(announcedReasons())->toBe([handleFor($old) => 'revoked', handleFor($lost) => 'password_reset'])
            ->and(sweepRow($lost->id)->announced_at)->toBe($now)
            ->and(sweepRow($recent->id)->announced_at)->toBeNull();

        // Once is enough.
        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 0 ended sessions again')->assertSuccessful();
        expect($this->announced)->toHaveCount(2);
    });

    it('tries a listener that failed again later each time, and gives up after a day', function () {
        $session = swept($this->user, unused: 9000);
        Exceptions::fake();
        Event::listen(function (RegisteredSessionEnded $event): never {
            throw new RuntimeException('The client app is down.');
        });
        $start = now()->getTimestamp();

        $this->artisan('keyring:sweep')->assertSuccessful();
        expect(sweepRow($session->id))->toMatchObject(['announced_at' => null, 'announce_attempts' => 1, 'announce_after' => $start + 300]);

        // Before its next try is due, it's left alone.
        $this->travel(299)->seconds();
        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 0 ended sessions again')->assertSuccessful();

        $tries = [$start];

        for ($run = 0; now()->getTimestamp() < $start + Sweep::GIVE_UP_AFTER + 3600; $run++) {
            $this->travel(60)->seconds();

            if (sweepRow($session->id)->announce_after <= now()->getTimestamp() && now()->getTimestamp() - $start < Sweep::GIVE_UP_AFTER) {
                $tries[] = now()->getTimestamp();
            }

            $this->artisan('keyring:sweep')->assertSuccessful();
        }

        // Five minutes, then doubling: 5, 15, 35, 75, 155, 315, 635 and 1275 minutes in.
        expect(array_map(fn (int $at) => intdiv($at - $start, 60), $tries))->toBe([0, 5, 15, 35, 75, 155, 315, 635, 1275])
            ->and($this->announced)->toHaveCount(9)
            ->and(sweepRow($session->id)->announced_at)->toBeNull();
        Exceptions::assertReportedCount(9);

        // Once it's given up on, pruning forgets it.
        $this->artisan('keyring:prune')->assertSuccessful();
        expect(DB::table('keyring_sessions')->where('id', $session->id)->exists())->toBeFalse();
    });

    it('announces a session lost during an outage of a couple of hours once the listener works again', function () {
        $session = swept($this->user, unused: 9000);
        Exceptions::fake();
        $outage = new ArrayObject(['down' => true]);
        Event::listen(function (RegisteredSessionEnded $event) use ($outage) {
            if ($outage['down']) {
                throw new RuntimeException('The client app is down.');
            }
        });

        for ($minutes = 0; $minutes < 120; $minutes += 5) {
            $this->artisan('keyring:sweep')->assertSuccessful();
            $this->travel(5)->minutes();
        }

        $outage['down'] = false;
        $this->travel(2)->hours();
        $this->artisan('keyring:sweep')->assertSuccessful();

        expect(sweepRow($session->id)->announced_at)->toBe(now()->getTimestamp());
    });

    it('gives lost announcements an allowance of their own, ahead of a backlog of timeouts', function () {
        config(['keyring.sessions.sweep_limit' => 2]);
        $now = now()->getTimestamp();
        collect([1, 2, 3])->each(fn () => swept($this->user, unused: 9000));
        $lost = collect([1, 2])->map(function () use ($now) {
            $session = swept($this->user);
            DB::table('keyring_sessions')->where('id', $session->id)->update(['revoked_at' => $now - 3600]);

            return handleFor($session);
        });

        $this->artisan('keyring:sweep')
            ->expectsOutputToContain('Ended 2 timed-out sessions, and announced 2 ended sessions again.')
            ->expectsOutputToContain('More are left')
            ->assertSuccessful();

        expect($this->announced->take(2)->pluck('handle')->sort()->values()->all())->toBe($lost->sort()->values()->all());
    });

    it('says more lost announcements are left when they fill the allowance', function () {
        config(['keyring.sessions.sweep_limit' => 1]);
        $now = now()->getTimestamp();
        collect([1, 2])->each(fn () => DB::table('keyring_sessions')->where('id', swept($this->user)->id)->update(['revoked_at' => $now - 3600]));

        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 1 ended sessions again')->expectsOutputToContain('More are left')->assertSuccessful();
    });

    it('counts a record whose event could not be made as a failed attempt', function () {
        $session = swept($this->user, unused: 9000);
        Exceptions::fake();
        config(['app.key' => null]);

        $this->artisan('keyring:sweep')->assertSuccessful();

        expect(sweepRow($session->id))->toMatchObject(['announced_at' => null, 'announce_attempts' => 1]);
    });

    it('sends a lost EveryoneSignedOut again, as itself, and never announces its sessions one by one', function () {
        $sessions = collect([1, 2, 3])->map(fn () => swept($this->user));
        Exceptions::fake();
        $everyone = new Collection;
        $outage = new ArrayObject(['down' => true]);
        Event::listen(function (EveryoneSignedOut $event) use ($everyone, $outage) {
            $everyone->push($event->at);

            if ($outage['down']) {
                throw new RuntimeException('The client app is down.');
            }
        });
        $at = now()->getTimestamp();

        app(SessionRegistry::class)->revokeEveryone();

        expect(DB::table('keyring_sessions')->whereNull('announced_at')->count())->toBe(3)
            ->and(sweepRow($sessions[0]->id)->end_reason)->toBe(DatabaseSessionRegistry::EVERYONE);

        $outage['down'] = false;
        $this->travel(Sweep::GRACE)->seconds();
        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 0 ended sessions again')->assertSuccessful();
        $this->artisan('keyring:sweep')->assertSuccessful();

        expect($everyone->all())->toBe([$at, $at])
            ->and($this->announced)->toBeEmpty()
            ->and(DB::table('keyring_sessions')->whereNull('announced_at')->count())->toBe(0);
    });

    it('sends the latest of two lost sign-outs of everyone, which settles both', function () {
        Exceptions::fake();
        $everyone = new Collection;
        $outage = new ArrayObject(['down' => true]);
        Event::listen(function (EveryoneSignedOut $event) use ($everyone, $outage) {
            $everyone->push($event->at);

            if ($outage['down']) {
                throw new RuntimeException('The client app is down.');
            }
        });

        swept($this->user);
        app(SessionRegistry::class)->revokeEveryone();
        $this->travel(60)->seconds();
        swept($this->user);
        $second = now()->getTimestamp();
        app(SessionRegistry::class)->revokeEveryone();

        $outage['down'] = false;
        $this->travel(Sweep::GRACE)->seconds();
        $this->artisan('keyring:sweep')->assertSuccessful();
        $this->artisan('keyring:sweep')->assertSuccessful();

        expect($everyone->slice(2)->values()->all())->toBe([$second])
            ->and(DB::table('keyring_sessions')->whereNull('announced_at')->count())->toBe(0);
    });

    it('tries a lost sign-out of everyone again later each time, and puts the next try off before each', function () {
        swept($this->user);
        Exceptions::fake();
        $tries = new Collection;
        $start = now()->getTimestamp();
        Event::listen(function (EveryoneSignedOut $event) use ($tries, $start): never {
            $tries->push(intdiv(now()->getTimestamp() - $start, 60));

            throw new RuntimeException('The client app is down.');
        });

        app(SessionRegistry::class)->revokeEveryone();

        for ($minutes = 0; $minutes < 160; $minutes++) {
            $this->travel(1)->minutes();
            $this->artisan('keyring:sweep')->assertSuccessful();
        }

        expect($tries->all())->toBe([0, 5, 15, 35, 75, 155])
            ->and(DB::table('keyring_sessions')->value('announce_attempts'))->toBe(6);
    });

    it('keeps a sign-out of everyone that was never announced until the sweep gives up on it', function () {
        swept($this->user);
        Exceptions::fake();
        Event::listen(fn (EveryoneSignedOut $event) => throw new RuntimeException('The client app is down.'));

        app(SessionRegistry::class)->revokeEveryone();
        $this->artisan('keyring:prune')->assertSuccessful();
        expect(DB::table('keyring_sessions')->count())->toBe(1);

        $this->travel(Sweep::GIVE_UP_AFTER)->seconds();
        $this->artisan('keyring:prune')->assertSuccessful();
        expect(DB::table('keyring_sessions')->count())->toBe(0);
    });

    it('ends what has timed out by the time the announcing before it is done', function () {
        $lost = swept($this->user);
        DB::table('keyring_sessions')->where('id', $lost->id)->update(['revoked_at' => now()->getTimestamp() - 3600]);
        $soon = swept($this->user, unused: 7000);

        // Announcing again takes long enough for another session to idle out.
        Event::listen(function (RegisteredSessionEnded $event) {
            if ($this->announced->count() === 1) {
                $this->travel(300)->seconds();
            }
        });

        $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 1 timed-out sessions, and announced 1 ended sessions again.')->assertSuccessful();

        expect(sweepRow($soon->id)->end_reason)->toBe('idle');
    });

    it('notes a great many announcements as it goes, not only at the end', function () {
        $then = now()->getTimestamp() - 9000;
        DB::table('keyring_sessions')->insert(collect(range(1, 501))->map(fn (int $i) => array_diff_key(new RegisteredSession(Str::random(40), (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, $then, $then, $then + 86400)->toArray(), ['origin' => true]))->all());
        $notedBeforeTheLast = null;
        Event::listen(function (RegisteredSessionEnded $event) use (&$notedBeforeTheLast) {
            if ($this->announced->count() === 501) {
                $notedBeforeTheLast = DB::table('keyring_sessions')->whereNotNull('announced_at')->count();
            }
        });

        $this->artisan('keyring:sweep')->assertSuccessful();

        expect($notedBeforeTheLast)->toBe(500);
    });

    it('notes everyone signed out as announced, so the sweep doesn\'t announce them one by one', function () {
        collect([1, 2, 3, 4, 5])->each(fn () => swept($this->user));

        app(SessionRegistry::class)->revokeEveryone();
        $this->travel(Sweep::GRACE + 1)->seconds();
        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 0 ended sessions again')->assertSuccessful();

        expect($this->announced)->toBeEmpty()
            ->and(DB::table('keyring_sessions')->whereNull('announced_at')->count())->toBe(0);
    });

    it('counts a failure once for each record failed together at different tries', function () {
        $sessions = collect([1, 2])->map(fn () => swept($this->user));
        app(SessionRegistry::class)->revokeAll($this->user);
        foreach ($sessions as $i => $session) {
            DB::table('keyring_sessions')->where('id', $session->id)->update(['announced_at' => null, 'announce_attempts' => $i + 1]);
        }
        $at = now()->getTimestamp();

        app(SessionRegistry::class)->inner()->announced([], $sessions->pluck('id')->all(), $at);

        // Each one step further along the back-off, none skipping one.
        expect(sweepRow($sessions[0]->id))->toMatchObject(['announce_attempts' => 2, 'announce_after' => $at + Sweep::retryAfter(2)])
            ->and(sweepRow($sessions[1]->id))->toMatchObject(['announce_attempts' => 3, 'announce_after' => $at + Sweep::retryAfter(3)]);
    });

    it('keeps why a session ended in the same write that revokes it', function () {
        $sessions = collect([1, 2])->map(fn () => swept($this->user));
        $queries = new Collection;
        DB::listen(fn ($query) => str_starts_with($query->sql, 'update') && $queries->push($query->sql));

        app(Sessions::class)->because(SessionEndReason::PasswordReset, fn () => app(SessionRegistry::class)->revokeAll($this->user));

        expect($sessions->map(fn (RegisteredSession $session) => sweepRow($session->id)->end_reason)->all())->toBe(['password_reset', 'password_reset'])
            ->and($queries->filter(fn (string $sql) => str_contains($sql, 'end_reason'))->count())->toBe(1);
    });
});

it('still ends and announces a session when noting it fails', function () {
    app(SessionRegistryManager::class)->extend('forgetful', fn () => new class(DB::connection(), 'keyring_sessions') extends DatabaseSessionRegistry
    {
        public function announced(array $announced, array $failed, int $at): void
        {
            throw new RuntimeException('The note could not be written.');
        }
    });
    config(['keyring.sessions.driver' => 'forgetful']);
    Exceptions::fake();
    $session = swept($this->user);

    expect(app(SessionRegistry::class)->revoke($session->id)?->revokedAt)->not->toBeNull()
        ->and($this->announced)->toHaveCount(1)
        ->and(sweepRow($session->id)->announced_at)->toBeNull();
    Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'The note could not be written.');
});

describe('a stale note that the migration is missing', function () {
    beforeEach(function () {
        // Left by a process that looked before the migration ran, in a
        // cache the migration couldn't clear.
        cache()->put(DatabaseSessionRegistry::schemaCacheKey(DB::connection(), 'keyring_sessions'), false, 300);
    });

    it('costs one second announcement at most, then the sweep sets it right', function () {
        $session = swept($this->user);

        // The request takes the cache's word, and notes nothing.
        app(SessionRegistry::class)->revoke($session->id);
        expect(sweepRow($session->id)->end_reason)->toBeNull();

        // The sweep asks the database, puts the cache right, and announces the
        // session again, once.
        $this->travel(Sweep::GRACE + 1)->seconds();
        $this->artisan('keyring:sweep')->assertSuccessful();
        $this->artisan('keyring:sweep')->assertSuccessful();

        expect($this->announced)->toHaveCount(2)
            ->and(sweepRow($session->id)->announced_at)->not->toBeNull()
            ->and(cache()->get(DatabaseSessionRegistry::schemaCacheKey(DB::connection(), 'keyring_sessions')))->toBeTrue();
    });

    it('still tries a failed announcement again until the listener takes it', function () {
        $session = swept($this->user);
        Exceptions::fake();
        $outage = new ArrayObject(['down' => true]);
        Event::listen(function (RegisteredSessionEnded $event) use ($outage) {
            if ($outage['down']) {
                throw new RuntimeException('The client app is down.');
            }
        });

        app(SessionRegistry::class)->revoke($session->id);
        expect(sweepRow($session->id)->announce_attempts)->toBe(0);

        $this->travel(Sweep::GRACE)->seconds();
        $this->artisan('keyring:sweep')->assertSuccessful();
        expect(sweepRow($session->id)->announce_attempts)->toBe(1);

        $outage['down'] = false;
        $this->travel(Sweep::retryAfter(1))->seconds();
        $this->artisan('keyring:sweep')->assertSuccessful();
        $this->artisan('keyring:sweep')->assertSuccessful();

        expect(sweepRow($session->id)->announced_at)->toBe(now()->getTimestamp())
            ->and($this->announced)->toHaveCount(3);
    });
});

describe('before the migration has run', function () {
    beforeEach(function () {
        (require __DIR__.'/../../database/migrations/2026_11_21_000001_add_announcements_to_keyring_sessions_table.php')->down();
    });

    it('still signs in and out and announces, and warns once a day', function () {
        Log::spy();
        $sessions = collect([1, 2, 3])->map(fn () => swept($this->user));

        app(SessionRegistry::class)->revoke($sessions[0]->id);

        $schema = fn (Collection $queries) => $queries->filter(fn (string $sql) => str_contains($sql, 'information_schema') || str_contains($sql, 'pg_attribute') || str_contains($sql, 'pragma') || str_contains($sql, 'sqlite_master'))->count();
        $queries = new Collection;
        DB::listen(fn ($query) => $queries->push($query->sql));
        app(SessionRegistryManager::class)->driver('database')->inner()->canSweep();
        $oneLook = $schema($queries);

        // A new process: nothing kept in it from the one before.
        app(SessionRegistryManager::class)->forgetDrivers();
        $queries->splice(0);
        app(SessionRegistry::class)->revoke($sessions[1]->id);

        expect($this->announced)->toHaveCount(2)
            ->and(app(SessionRegistry::class)->find($sessions[1]->id)->revokedAt)->not->toBeNull()
            // Nothing on the request's path asks the database: it takes the
            // cache's word.
            ->and($oneLook)->toBeGreaterThan(0)
            ->and($schema($queries))->toBe(0);
        Log::shouldHaveReceived('warning')->once()->withArgs(fn (string $message) => str_contains($message, 'Publish and run Keyring\'s migrations'));

        // A day later it looks again.
        $this->travel(Sweep::GIVE_UP_AFTER + 1)->seconds();
        app(SessionRegistryManager::class)->forgetDrivers();
        app(SessionRegistry::class)->revoke($sessions[2]->id);
        Log::shouldHaveReceived('warning')->twice();
    });

    it('starts noting at once when the migration runs', function () {
        $session = swept($this->user);
        app(SessionRegistry::class)->revoke(swept($this->user)->id);

        (require __DIR__.'/../../database/migrations/2026_11_21_000001_add_announcements_to_keyring_sessions_table.php')->up();
        app(SessionRegistryManager::class)->forgetDrivers();
        app(SessionRegistry::class)->revoke($session->id);

        expect(sweepRow($session->id)->announced_at)->toBe(now()->getTimestamp());
    });

    it('still signs everyone out, and says so', function () {
        $session = swept($this->user);
        $everyone = new Collection;
        Event::listen(fn (EveryoneSignedOut $event) => $everyone->push($event));

        app(SessionRegistry::class)->revokeEveryone();

        expect($everyone)->toHaveCount(1)
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
    });

    it('refuses to sweep, and says how to fix it', function () {
        $this->artisan('keyring:sweep')->expectsOutputToContain('Publish and run Keyring\'s migrations')->assertFailed();
    });

    it('prunes as it always has, whatever the sweep is set to', function () {
        config(['keyring.sessions.sweep_every' => '5m']);
        $expired = swept($this->user, expiresIn: -1);
        $revoked = swept($this->user);
        app(SessionRegistry::class)->revoke($revoked->id);
        $queries = new Collection;
        DB::listen(fn ($query) => str_starts_with($query->sql, 'delete') && $queries->push($query->sql));

        expect(app(SessionRegistry::class)->prune())->toBe(2)
            ->and(app(SessionRegistry::class)->find($expired->id))->toBeNull()
            ->and($queries->all())->toBe(['delete from "keyring_sessions" where "expires_at" <= ? or ("revoked_at" is not null and "replaced_by" is null)']);
    })->skip(fn () => DB::connection()->getDriverName() !== 'sqlite', 'The SQL is compared as SQLite writes it.');
});

describe('once the migration has run', function () {
    beforeEach(function () {
        $this->schemaQueries = new Collection;
        DB::listen(fn ($query) => (str_contains($query->sql, 'information_schema') || str_contains($query->sql, 'pg_attribute') || str_contains($query->sql, 'pragma') || str_contains($query->sql, 'sqlite_master')) && $this->schemaQueries->push($query->sql));
        $this->migration = require __DIR__.'/../../database/migrations/2026_11_21_000001_add_announcements_to_keyring_sessions_table.php';
    });

    it('keeps the answer, so a fresh process revokes with no schema query', function () {
        $sessions = collect([1, 2, 3])->map(fn () => swept($this->user));

        app(SessionRegistry::class)->revoke($sessions[0]->id);
        expect($this->schemaQueries)->not->toBeEmpty();

        // New processes: nothing kept in them from the one before.
        foreach ([1, 2] as $i) {
            app(SessionRegistryManager::class)->forgetDrivers();
            $this->schemaQueries->splice(0);
            app(SessionRegistry::class)->revoke($sessions[$i]->id);

            expect($this->schemaQueries)->toBeEmpty()
                ->and(sweepRow($sessions[$i]->id)->end_reason)->toBe('revoked');
        }
    });

    it('stops noting when it is rolled back, and still signs out', function () {
        app(SessionRegistry::class)->revoke(swept($this->user)->id);
        $session = swept($this->user);

        $this->migration->down();
        app(SessionRegistryManager::class)->forgetDrivers();

        expect(app(SessionRegistry::class)->revoke($session->id)?->revokedAt)->not->toBeNull()
            ->and($this->announced)->toHaveCount(2)
            ->and(cache()->get(DatabaseSessionRegistry::schemaCacheKey(DB::connection(), 'keyring_sessions')))->toBeFalse();
    });

    it('signs out again without the notes where a process found the columns before they went', function (Closure $revoke, int $ended) {
        $registry = app(SessionRegistry::class);
        $registry->revoke(swept($this->user)->id);
        $key = DatabaseSessionRegistry::schemaCacheKey(DB::connection(), 'keyring_sessions');

        // Rolled back where the cache that said yes couldn't be cleared.
        $this->migration->down();

        // This process found the columns itself, the next takes the cache's word.
        foreach ([$registry, app(SessionRegistryManager::class)->forgetDrivers()->driver()] as $registry) {
            cache()->put($key, true, 300);
            $session = swept($this->user);

            expect($revoke($registry, $session, $this->user))->toBe($ended)
                ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull()
                // Forgotten, and asked again.
                ->and(cache()->get($key))->toBeFalse();
        }
    })->with([
        'one session' => [fn (SessionRegistry $registry, RegisteredSession $session) => $registry->revoke($session->id) === null ? 0 : 1, 1],
        'a user\'s sessions' => [fn (SessionRegistry $registry, RegisteredSession $session, User $user) => $registry->revokeAll($user)->count(), 1],
        'everyone' => [function (SessionRegistry $registry) {
            $registry->revokeEveryone();

            return 0;
        }, 0],
    ]);

});

it('counts what was revoked before the migration as announced', function () {
    $migration = require __DIR__.'/../../database/migrations/2026_11_21_000001_add_announcements_to_keyring_sessions_table.php';
    $migration->down();

    $revoked = swept($this->user);
    $live = swept($this->user);
    DB::table('keyring_sessions')->where('id', $revoked->id)->update(['revoked_at' => now()->getTimestamp() - 3600]);

    $migration->up();

    expect(sweepRow($revoked->id)->announced_at)->toBe(now()->getTimestamp() - 3600)
        ->and(sweepRow($live->id)->announced_at)->toBeNull();

    $this->artisan('keyring:sweep')->expectsOutputToContain('announced 0 ended sessions again')->assertSuccessful();
});

it('has nothing to sweep on the cache driver, and says so', function () {
    config(['keyring.sessions.driver' => 'cache']);

    $this->artisan('keyring:sweep')->expectsOutputToContain('The [cache] session registry driver has nothing to sweep.')->assertSuccessful();

    expect(app(SessionRegistryManager::class)->driver()->sweep(10, 60, 60))->toBeNull()
        ->and(app(SessionRegistry::class)->inner())->toBeInstanceOf(CacheSessionRegistry::class);
});

describe('pruning', function () {
    beforeEach(function () {
        $now = now()->getTimestamp();

        $this->rows = [
            'timed out' => swept($this->user, expiresIn: -1),
            'expired over a day ago' => swept($this->user, expiresIn: -Sweep::GIVE_UP_AFTER),
            'live' => swept($this->user),
            'announced' => swept($this->user),
            'unannounced' => swept($this->user),
            'given up on' => swept($this->user),
            'moved and expired' => swept($this->user, expiresIn: -1, changes: ['replacedBy' => 'elsewhere']),
            'moved' => swept($this->user, changes: ['replacedBy' => 'elsewhere']),
        ];

        DB::table('keyring_sessions')->where('id', $this->rows['announced']->id)->update(['revoked_at' => $now, 'announced_at' => $now]);
        DB::table('keyring_sessions')->where('id', $this->rows['unannounced']->id)->update(['revoked_at' => $now]);
        DB::table('keyring_sessions')->where('id', $this->rows['given up on']->id)->update(['revoked_at' => $now - Sweep::GIVE_UP_AFTER]);
        DB::table('keyring_sessions')->where('id', $this->rows['moved']->id)->update(['revoked_at' => $now]);
    });

    $kept = fn () => collect($this->rows)->filter(fn (RegisteredSession $session) => DB::table('keyring_sessions')->where('id', $session->id)->exists())->keys()->all();

    // Whether a sweep is scheduled, scheduled by the app itself, or failing:
    // what's left is the same, and nothing outlives its expiry by more
    // than a day.
    it('leaves what a sweep has still to do, whether or not one is scheduled', function (mixed $every) use ($kept) {
        config(['keyring.sessions.sweep_every' => $every]);

        $this->artisan('keyring:prune')->expectsOutputToContain('Pruned 4 ended sessions.')->assertSuccessful();

        expect($kept->call($this))->toBe(['timed out', 'live', 'unannounced', 'moved']);
    })->with([
        'scheduled' => ['5m'],
        'never scheduled, or scheduled by the app' => [null],
    ]);

    it('leaves what a sweep that keeps failing has to do, up to a day past its expiry', function () use ($kept) {
        app(SessionRegistryManager::class)->extend('failing', fn () => new class(DB::connection(), 'keyring_sessions') extends DatabaseSessionRegistry
        {
            public function sweep(int $now, ?int $idle, ?int $rememberedIdle, int $limit): array
            {
                throw new RuntimeException('The sweep failed.');
            }
        });
        config(['keyring.sessions.driver' => 'failing']);

        expect(fn () => $this->artisan('keyring:sweep'))->toThrow(RuntimeException::class);

        // A day on, what timed out back then, and the revocations nobody
        // announced, are gone. The one that was live has only just expired.
        $this->travel(Sweep::GIVE_UP_AFTER)->seconds();
        $this->artisan('keyring:prune')->assertSuccessful();

        expect($kept->call($this))->toBe(['live']);
    });
});

describe('scheduling', function () {
    $sweeps = function () {
        app()->forgetInstance(Schedule::class);

        return collect(app(Schedule::class)->events())->values();
    };

    it('schedules no sweep until sweep_every is set', function () use ($sweeps) {
        expect($sweeps()->filter(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:sweep')))->toBeEmpty()
            ->and(Sweep::on())->toBeFalse();
    });

    it('sweeps as often as sweep_every says, one at a time on one server, before the prune', function (string $every, string $expression, int $lock) use ($sweeps) {
        config(['keyring.sessions.sweep_every' => $every]);
        $events = $sweeps();
        $sweep = $events->search(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:sweep'));
        $prune = $events->search(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:prune'));

        expect($events[$sweep]->expression)->toBe($expression)
            ->and($events[$sweep]->withoutOverlapping)->toBeTrue()
            ->and($events[$sweep]->expiresAt)->toBe($lock)
            ->and($events[$sweep]->onOneServer)->toBeTrue()
            ->and($sweep)->toBeLessThan($prune);
    })->with([
        ['5m', '*/5 * * * *', 10],
        ['30s', '*/1 * * * *', 10],
        ['15', '*/1 * * * *', 10],
        ['2h', '0 */2 * * *', 240],
        ['12h', '0 */12 * * *', 360],
    ]);

    it('warns of a setting it can\'t use once a day, though the schedule is read every minute', function () use ($sweeps) {
        Log::spy();
        config(['keyring.sessions.sweep_every' => 'often']);

        $sweeps();
        $sweeps();
        Log::shouldHaveReceived('warning')->once();

        $this->travel(Sweep::GIVE_UP_AFTER + 1)->seconds();
        $sweeps();
        Log::shouldHaveReceived('warning')->twice();
    });

    it('runs no less often than every 12 hours, and says so', function (string $every) use ($sweeps) {
        Log::spy();
        config(['keyring.sessions.sweep_every' => $every]);

        expect($sweeps()->first(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:sweep'))->expression)->toBe('0 */12 * * *');
        Log::shouldHaveReceived('warning')->withArgs(fn (string $message) => str_contains($message, 'longer than 12 hours'));

        $this->artisan('keyring:sweep')->expectsOutputToContain('longer than 12 hours')->assertSuccessful();
    })->with(['13h', '1d', '7d']);

    it('takes anything that isn\'t a duration as off, warns, and leaves the rest of the schedule alone', function (mixed $every, string $warning) use ($sweeps) {
        Log::spy();
        config(['keyring.sessions.sweep_every' => $every]);
        $events = $sweeps();

        expect($events->filter(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:sweep')))->toBeEmpty()
            ->and($events->filter(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:prune')))->toHaveCount(1)
            ->and(Sweep::on())->toBeFalse();
        Log::shouldHaveReceived('warning')->withArgs(fn (string $message) => str_contains($message, $warning));

        $this->artisan('keyring:sweep')->expectsOutputToContain($warning)->assertSuccessful();
    })->with([
        'junk' => ['often', 'isn\'t a duration'],
        'spaced out' => ['5 min', 'isn\'t a duration'],
        'zero' => ['0', 'is zero'],
        'a list' => [['5m'], 'isn\'t a duration'],
        'true' => [true, 'isn\'t a duration'],
    ]);
});

it('ends what the middleware would, and the middleware agrees afterwards', function (array $config, int $away, string $reason) {
    config($config);
    $ended = new Collection;
    Event::listen(fn (SessionEnded $event) => $ended->push($event->reason));
    $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $here = app(SessionRegistry::class)->find(session(Sessions::KEY));

    $this->travel($away)->seconds();
    $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 1 timed-out sessions')->assertSuccessful();

    $this->get('/home')->assertRedirect('/login');

    // Told why it timed out, as it would be had nothing swept it first,
    // and announced once.
    expect(announcedReasons())->toBe([handleFor($here) => $reason])
        ->and($ended->all())->toBe([$reason])
        ->and(SecurityEvent::query()->where('type', 'session_ended')->sole()->meta['reason'])->toBe($reason);
})->with([
    'idle' => [[], 7201, 'idle'],
    'expired' => [['keyring.sessions.absolute' => '1h'], 3601, 'expired'],
]);

it('tells a browser whose session timed out unswept, then was signed out everywhere, that it idled out', function () {
    $ended = new Collection;
    Event::listen(fn (SessionEnded $event) => $ended->push($event->reason));
    $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $this->travel(7201)->seconds();
    app(Sessions::class)->signOutEverywhere($this->user);

    $this->get('/home')->assertRedirect('/login');

    expect($ended->all())->toBe(['idle']);
});

it('is the one driver the manager hands out, wrapped', function () {
    expect(app(SessionRegistryManager::class)->driver())->toBeInstanceOf(AnnouncingSessionRegistry::class);
});
