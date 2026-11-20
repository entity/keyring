<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Event as ScheduledEvent;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\RegisteredSessionEnded;
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
            ->expectsOutputToContain('More are left than one run may take (2).')
            ->assertSuccessful();

        $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 1 timed-out sessions')->doesntExpectOutputToContain('More are left')->assertSuccessful();

        expect($this->announced)->toHaveCount(3);
    });

    it('says more are left while a timed-out session is still to be ended', function () {
        swept($this->user, unused: 9000);
        $registry = app(SessionRegistryManager::class)->driver();

        expect($registry->sweeper()->timedOut(now()->getTimestamp(), 7200, null))->toBeTrue()
            ->and($registry->sweep(1, 7200, null)->more)->toBeTrue()
            ->and($registry->sweeper()->timedOut(now()->getTimestamp(), 7200, null))->toBeFalse();
    });

    it('takes its limit from config only when it is a positive number', function (mixed $limit, int $taken) {
        config(['keyring.sessions.sweep_limit' => $limit]);

        expect(Sweep::limit())->toBe($taken);
    })->with([
        [50, 50],
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

    it('tries a listener that failed again on the next runs, then stops', function () {
        $session = swept($this->user, unused: 9000);
        Exceptions::fake();
        Event::listen(function (RegisteredSessionEnded $event): never {
            throw new RuntimeException('The client app is down.');
        });

        $this->artisan('keyring:sweep')->assertSuccessful();
        expect(sweepRow($session->id))->toMatchObject(['announced_at' => null, 'announce_attempts' => 1]);

        $this->travel(Sweep::GRACE)->seconds();
        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 1 ended sessions again')->assertSuccessful();
        expect(sweepRow($session->id))->toMatchObject(['announced_at' => null, 'announce_attempts' => 2]);

        // The last attempt allowed counts it announced, whatever the listener does.
        $this->artisan('keyring:sweep')->assertSuccessful();
        expect(sweepRow($session->id))->toMatchObject(['announced_at' => now()->getTimestamp(), 'announce_attempts' => 3]);

        $this->travel(Sweep::GRACE)->seconds();
        $this->artisan('keyring:sweep')->expectsOutputToContain('announced 0 ended sessions again')->assertSuccessful();

        expect($this->announced)->toHaveCount(3);
        Exceptions::assertReportedCount(3);
    });

    it('announces again only what the run has room left for', function () {
        config(['keyring.sessions.sweep_limit' => 2]);
        $now = now()->getTimestamp();
        swept($this->user, unused: 9000);
        collect([1, 2])->each(fn () => DB::table('keyring_sessions')->where('id', swept($this->user)->id)->update(['revoked_at' => $now - 3600]));

        $this->artisan('keyring:sweep')
            ->expectsOutputToContain('Ended 1 timed-out sessions, and announced 1 ended sessions again.')
            ->expectsOutputToContain('More are left')
            ->assertSuccessful();
    });

    it('counts a record whose event could not be made as a failed attempt', function () {
        $session = swept($this->user, unused: 9000);
        Exceptions::fake();
        config(['app.key' => null]);

        $this->artisan('keyring:sweep')->assertSuccessful();

        expect(sweepRow($session->id))->toMatchObject(['announced_at' => null, 'announce_attempts' => 1]);
    });
});

it('still ends and announces a session when noting it fails', function () {
    app(SessionRegistryManager::class)->extend('forgetful', fn () => new class(DB::connection(), 'keyring_sessions') extends DatabaseSessionRegistry
    {
        public function announced(array $announced, array $failed, int $at, int $attempts): void
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

describe('before the migration has run', function () {
    beforeEach(function () {
        Schema::table('keyring_sessions', function (Blueprint $table) {
            $table->dropIndex(['last_activity_at']);
            $table->dropIndex(['revoked_at']);
            $table->dropColumn(['announced_at', 'end_reason', 'announce_attempts']);
        });
    });

    it('still signs in and out, announces, and says once what is missing', function () {
        Exceptions::fake();
        $first = swept($this->user);
        $second = swept($this->user);

        app(SessionRegistry::class)->revoke($first->id);
        app(SessionRegistry::class)->revoke($second->id);

        expect($this->announced)->toHaveCount(2)
            ->and(app(SessionRegistry::class)->find($first->id)->revokedAt)->not->toBeNull();
        Exceptions::assertReportedCount(1);
        Exceptions::assertReported(fn (RuntimeException $e) => str_contains($e->getMessage(), 'publish and run Keyring\'s migrations'));
    });

    it('refuses to sweep, and says how to fix it', function () {
        $this->artisan('keyring:sweep')->expectsOutputToContain('Publish and run Keyring\'s migrations')->assertFailed();
    });

    it('prunes as it always has, though the sweep is on', function () {
        config(['keyring.sessions.sweep_every' => '5m']);
        $expired = swept($this->user, expiresIn: -1);

        expect(app(SessionRegistry::class)->prune())->toBe(1)
            ->and(app(SessionRegistry::class)->find($expired->id))->toBeNull();
    });
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

    it('forgets every expired or revoked record with the sweep off', function () use ($kept) {
        $this->artisan('keyring:prune')->assertSuccessful();

        expect($kept->call($this))->toBe(['live', 'moved']);
    });

    it('leaves what the sweep has still to do with the sweep on', function () use ($kept) {
        config(['keyring.sessions.sweep_every' => '5m']);

        $this->artisan('keyring:prune')->expectsOutputToContain('Pruned 3 ended sessions.')->assertSuccessful();

        expect($kept->call($this))->toBe(['timed out', 'live', 'unannounced', 'moved']);
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

    it('sweeps as often as sweep_every says, one at a time on one server, before the prune', function (string $every, string $expression) use ($sweeps) {
        config(['keyring.sessions.sweep_every' => $every]);
        $events = $sweeps();
        $sweep = $events->search(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:sweep'));
        $prune = $events->search(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:prune'));

        expect($events[$sweep]->expression)->toBe($expression)
            ->and($events[$sweep]->withoutOverlapping)->toBeTrue()
            ->and($events[$sweep]->onOneServer)->toBeTrue()
            ->and($sweep)->toBeLessThan($prune);
    })->with([
        ['5m', '*/5 * * * *'],
        ['30s', '*/1 * * * *'],
        ['2h', '0 */2 * * *'],
        ['1d', '0 0 * * *'],
        ['15', '*/1 * * * *'],
    ]);

    it('takes anything that isn\'t a duration as off', function (mixed $every) use ($sweeps) {
        config(['keyring.sessions.sweep_every' => $every]);

        expect($sweeps()->filter(fn (ScheduledEvent $event) => str_contains((string) $event->command, 'keyring:sweep')))->toBeEmpty()
            ->and(Sweep::on())->toBeFalse();
    })->with([
        'junk' => ['often'],
        'zero' => ['0'],
        'a list' => [['5m']],
        'true' => [true],
    ]);
});

it('ends what the middleware would, and the middleware agrees afterwards', function () {
    $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $here = app(SessionRegistry::class)->find(session(Sessions::KEY));

    $this->travel(7201)->seconds();
    $this->artisan('keyring:sweep')->expectsOutputToContain('Ended 1 timed-out sessions')->assertSuccessful();

    $this->get('/home')->assertRedirect('/login');

    expect(announcedReasons())->toBe([handleFor($here) => 'idle']);
});

it('is the one driver the manager hands out, wrapped', function () {
    expect(app(SessionRegistryManager::class)->driver())->toBeInstanceOf(AnnouncingSessionRegistry::class);
});
