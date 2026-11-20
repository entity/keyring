<?php

declare(strict_types=1);

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Eloquent\Attributes\Table;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Encryption\MissingAppKeyException;
use Illuminate\Http\Request;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Keyring\Changes\EmailChanges;
use Keyring\Changes\PasswordChanges;
use Keyring\Changes\PasswordHolds;
use Keyring\Contracts\SessionRegistry;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Assurance;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\EmailChangeReverted;
use Keyring\Events\EveryoneSignedOut;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Events\SessionEnded;
use Keyring\Exceptions\PartialRevocation;
use Keyring\Facades\Keyring;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\EmailChangeNotice;
use Keyring\Risk\Action;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Risk;
use Keyring\Risk\RiskEngine;
use Keyring\Risk\RiskLocks;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\AnnouncingSessionRegistry;
use Keyring\Sessions\CacheSessionRegistry;
use Keyring\Sessions\DatabaseSessionRegistry;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\SoftDeletingUser;
use Keyring\Tests\Fixtures\User;
use Symfony\Component\HttpFoundation\Response;

dataset('session drivers', ['database', 'cache']);

beforeEach(function () {
    Notification::fake();
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    $this->user = taylor();

    // Every announcement, in the order it went out, heard by a listener
    // like any other.
    $this->announced = new Collection;
    Event::listen(fn (RegisteredSessionEnded $event) => $this->announced->push($event));
});

/**
 * Sign in from a browser, as a person would. Returns the session's record.
 */
function signInHere(array $cookies = []): string
{
    test()->withHeader('User-Agent', FIREFOX)->withCookies($cookies)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');

    return session(Sessions::KEY);
}

/**
 * A session of the user's somewhere else.
 */
function sessionElsewhere(User $user, ?string $device = null, int $activeAgo = 0, ?string $id = null): RegisteredSession
{
    $now = now()->getTimestamp();

    app(SessionRegistry::class)->save($session = new RegisteredSession($id ?? Str::random(40), (string) $user->getKey(), RegisteredSession::typeOf($user), 'web', $device, Assurance::AAL1, null, null, $now, $now - $activeAgo, $now + 3600));

    return $session;
}

/**
 * Move a session to a new record, as "remember me" does. Returns the
 * record it moved to.
 */
function moveSession(RegisteredSession $session): RegisteredSession
{
    $moved = $session->with(['id' => Str::random(40), 'origin' => $session->origin()]);

    expect(app(SessionRegistry::class)->replace($session->id, $moved))->toBeTrue();

    return $moved;
}

/**
 * A session elsewhere that has moved to a new record since it started.
 * Returns its handle, from before it moved, and the record it's on now.
 *
 * @return array{string, RegisteredSession}
 */
function movedSessionElsewhere(User $user, ?string $device = null, int $activeAgo = 0): array
{
    $first = sessionElsewhere($user, $device, $activeAgo);
    $handle = app(Sessions::class)->handle($first);

    return [$handle, moveSession($first)];
}

function handleOf(string $id): string
{
    return app(Sessions::class)->handle(app(SessionRegistry::class)->find($id));
}

/**
 * The session with this handle was announced once, as ended for this reason.
 */
function expectEnded(string $handle, SessionEndReason $reason, ?User $user = null): RegisteredSessionEnded
{
    $user ??= test()->user;
    $announced = test()->announced->filter(fn (RegisteredSessionEnded $event) => $event->handle === $handle);

    expect($announced)->toHaveCount(1);

    $event = $announced->first();

    expect($event->reason)->toBe($reason)
        ->and($event->handles)->toBe([$handle])
        ->and($event->userId)->toBe((string) $user->getKey())
        ->and($event->userType)->toBe(RegisteredSession::typeOf($user))
        ->and($event->guard)->toBe('web');

    return $event;
}

/**
 * A listener that hears each announcement, then throws.
 */
function throwingListener(): void
{
    Exceptions::fake();
    Event::listen(fn (RegisteredSessionEnded $event) => throw new RuntimeException('A listener failed.'));
}

/**
 * Ask for an email change from this browser. Returns the links' tokens.
 *
 * @return array{confirm: string, revert: string, current: string}
 */
function requestEmailChange(): array
{
    test()->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    $confirm = $notice = null;

    Notification::assertSentTo(new AnonymousNotifiable, ConfirmEmailChange::class, function ($notification) use (&$confirm) {
        return (bool) ($confirm = Str::afterLast($notification->url, '/'));
    });
    Notification::assertSentTo(new AnonymousNotifiable, EmailChangeNotice::class, function ($notification) use (&$notice) {
        return (bool) ($notice = $notification);
    });

    return ['confirm' => $confirm, 'revert' => Str::afterLast($notice->revertUrl, '/'), 'current' => Str::afterLast((string) $notice->confirmUrl, '/')];
}

/**
 * Keep the registry on a connection of its own: an SQLite file next to
 * whatever the users are on.
 */
function registryOnItsOwnConnection(): string
{
    $file = tempnam(sys_get_temp_dir(), 'keyring-sessions-');
    test()->beforeApplicationDestroyed(fn () => File::delete($file));

    config([
        'database.connections.sessions' => ['driver' => 'sqlite', 'database' => $file, 'prefix' => '', 'foreign_key_constraints' => false],
        'keyring.sessions.connection' => 'sessions',
    ]);

    Schema::connection('sessions')->create('keyring_sessions', function (Blueprint $table) {
        $table->string('id', 64)->primary();
        $table->string('user_id');
        $table->string('user_type');
        $table->string('guard');
        $table->string('device_id', 26)->nullable();
        $table->unsignedTinyInteger('assurance')->default(0);
        $table->string('ip', 45)->nullable();
        $table->text('user_agent')->nullable();
        $table->unsignedInteger('authenticated_at');
        $table->unsignedInteger('last_activity_at');
        $table->unsignedInteger('expires_at');
        $table->unsignedInteger('revoked_at')->nullable();
        $table->string('replaced_by', 64)->nullable();
        $table->unsignedInteger('replaced_at')->nullable();
        $table->boolean('remembered')->default(false);
        $table->string('origin', 64)->nullable();
    });

    return 'sessions';
}

describe('every way a session ends', function () {
    it('announces signing out, by the handle the session had before it moved', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $here = signInHere();
        $handle = handleOf($here);

        // As "remember me" or a step-up on the cookie session driver does.
        $moved = moveSession(app(SessionRegistry::class)->find($here));
        session()->put(Sessions::KEY, $moved->id);

        expect($this->announced)->toBeEmpty();

        $this->post('/logout');

        expectEnded($handle, SessionEndReason::LoggedOut);
        expect($this->announced)->toHaveCount(1);
    })->with('session drivers');

    it('announces ending this session from the sessions list as signing out', function () {
        $handle = handleOf(signInHere());

        $this->deleteJson(route('keyring.sessions.destroy', $handle))->assertNoContent();

        expectEnded($handle, SessionEndReason::LoggedOut);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces each session signing out everywhere else ends, and none it leaves', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        signInHere();
        [$handle] = movedSessionElsewhere($this->user);
        app(SessionRegistry::class)->revoke(sessionElsewhere($this->user)->id);
        $this->announced->splice(0);

        $this->deleteJson(route('keyring.sessions.destroy-others'))->assertOk();

        expectEnded($handle, SessionEndReason::SignedOutEverywhere);
        expect($this->announced)->toHaveCount(1);
    })->with('session drivers');

    it('announces a session ended from the sessions list', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        signInHere();
        [$handle] = movedSessionElsewhere($this->user);

        $this->deleteJson(route('keyring.sessions.destroy', $handle))->assertOk();

        expectEnded($handle, SessionEndReason::Revoked);
        expect($this->announced)->toHaveCount(1);
    })->with('session drivers');

    it('announces the sessions of a device signed out from the devices list', function () {
        signInHere();
        $device = $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'laptop'), 'last_seen_at' => now()]);
        [$handle] = movedSessionElsewhere($this->user, $device->id);

        $this->deleteJson(route('keyring.devices.destroy', $device->id))->assertOk();

        expectEnded($handle, SessionEndReason::DeviceRevoked);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces this browser signed out with its device, whatever device its record had', function () {
        $token = $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->getCookie('known_device')->getValue();
        $here = session(Sessions::KEY);
        $handle = handleOf($here);
        app(SessionRegistry::class)->update($here, ['deviceId' => null]);

        $this->withCookie('known_device', $token)->delete(route('keyring.devices.destroy', Device::sole()->id))->assertRedirect(route('login'));

        expectEnded($handle, SessionEndReason::DeviceRevoked);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces the sessions of a reported device', function () {
        $device = $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'laptop'), 'last_seen_at' => now()]);
        [$handle] = movedSessionElsewhere($this->user, $device->id);

        app(DeviceManager::class)->revoke($device, reported: true);

        expectEnded($handle, SessionEndReason::DeviceReported);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces the sessions of a device forgotten for the device limit', function () {
        config(['keyring.devices.limit' => 1]);
        $old = $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'old'), 'last_seen_at' => now()->subDay()]);
        [$handle] = movedSessionElsewhere($this->user, $old->id);

        signInHere();

        expectEnded($handle, SessionEndReason::DeviceLimit);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces the session a sign in past sessions.max ends', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => 1]);
        [$handle] = movedSessionElsewhere($this->user, activeAgo: 60);

        signInHere();

        expectEnded($handle, SessionEndReason::SessionLimit);
        expect($this->announced)->toHaveCount(1);
    })->with('session drivers');

    it('announces the session a browser leaves when it signs in again', function () {
        [$handle, $moved] = movedSessionElsewhere($this->user);
        $request = Request::create('/');
        $request->setLaravelSession(app('session.store'));
        $request->session()->put(Sessions::KEY, $moved->id);

        app(Sessions::class)->start($request, $this->user, null, Assurance::AAL1);

        expectEnded($handle, SessionEndReason::SignedInAgain);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces the sessions of a deleted user', function () {
        [$handle] = movedSessionElsewhere($this->user);

        $this->user->delete();

        expectEnded($handle, SessionEndReason::AccountDeleted);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces the sessions of a soft deleted user', function () {
        Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
        $user = SoftDeletingUser::findOrFail($this->user->id);
        [$handle] = movedSessionElsewhere($user);

        $user->delete();

        expectEnded($handle, SessionEndReason::AccountDeleted, $user);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces the sessions a risk response ends, this one included', function () {
        Keyring::risk()->signals([new SessionFingerprintChanged(score: 95)])
            ->respond(fn (Risk $risk, Checkpoint $at) => $at === Checkpoint::Request && $risk->isElevated() ? Action::deny()->revokeAllSessions() : Action::allow());
        $here = handleOf(signInHere());
        [$elsewhere] = movedSessionElsewhere($this->user);

        $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');

        expectEnded($here, SessionEndReason::Risk);
        expectEnded($elsewhere, SessionEndReason::Risk);
        expect($this->announced)->toHaveCount(2);
    });

    it('announces the sessions undoing an email change ends', function () {
        $here = handleOf(signInHere());
        [$elsewhere] = movedSessionElsewhere($this->user);
        $tokens = requestEmailChange();

        expect(app(EmailChanges::class)->revert(PendingChange::sole(), $tokens['revert']))->toBeTrue();

        expectEnded($here, SessionEndReason::EmailChangeUndone);
        expectEnded($elsewhere, SessionEndReason::EmailChangeUndone);
        expect($this->announced)->toHaveCount(2);
    });

    it('announces the other sessions a changed email address ends', function () {
        signInHere();
        [$elsewhere] = movedSessionElsewhere($this->user);
        $tokens = requestEmailChange();
        $change = PendingChange::sole();

        app(EmailChanges::class)->confirm($change, $tokens['current']);
        app(EmailChanges::class)->confirm($change->fresh(), $tokens['confirm']);

        expect($this->user->fresh()->email)->toBe('new@example.com');
        expectEnded($elsewhere, SessionEndReason::EmailChanged);
    });

    it('announces the other sessions a password change ends', function () {
        $here = signInHere();
        [$elsewhere] = movedSessionElsewhere($this->user);

        app(PasswordChanges::class)->change($this->user, fn () => $this->user->forceFill(['password' => 'a brand new passphrase'])->save(), currentSession: $here);

        expectEnded($elsewhere, SessionEndReason::PasswordChanged);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces every session a password reset ends', function () {
        [$elsewhere] = movedSessionElsewhere($this->user);

        app(PasswordChanges::class)->reset($this->user, fn () => $this->user->forceFill(['password' => 'a brand new passphrase'])->save());

        expectEnded($elsewhere, SessionEndReason::PasswordReset);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces a session the middleware finds idle', function () {
        $handle = handleOf(signInHere());

        $this->travel(3)->hours();
        $this->get('/home')->assertRedirect('/login');

        expectEnded($handle, SessionEndReason::Idle);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces a session the middleware finds past its absolute limit', function () {
        $here = signInHere();
        $handle = handleOf($here);
        app(SessionRegistry::class)->update($here, ['expiresAt' => now()->getTimestamp() - 1]);

        $this->get('/home')->assertRedirect('/login');

        expectEnded($handle, SessionEndReason::Expired);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces a session whose "remember me" was used twice, once', function () {
        $here = signInHere();
        $handle = handleOf($here);

        // "Remember me" carried it on elsewhere; this browser still holds the old record.
        $moved = moveSession(app(SessionRegistry::class)->find($here));

        $this->get('/home')->assertRedirect('/login');

        expect(app(SessionRegistry::class)->find($moved->id)->revokedAt)->not->toBeNull();
        expectEnded($handle, SessionEndReason::Reused);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces every session of an account the app keeps out', function () {
        $here = handleOf(signInHere());
        [$elsewhere] = movedSessionElsewhere($this->user);
        Keyring::allowSignInWhen(fn () => false);

        $this->get('/home')->assertRedirect('/login');

        expectEnded($here, SessionEndReason::NotAllowed);
        expectEnded($elsewhere, SessionEndReason::NotAllowed);
        expect($this->announced)->toHaveCount(2);
    });

    it('announces a record the middleware finds is another user\'s, as theirs', function () {
        $other = User::create(['name' => 'Someone', 'email' => 'someone@example.com', 'password' => 'password']);
        $here = signInHere();
        $handle = handleOf($here);
        app(SessionRegistry::class)->update($here, ['userId' => (string) $other->id]);

        $this->get('/home')->assertRedirect('/login');

        expectEnded($handle, SessionEndReason::OtherUser, $other);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces an administrator signing a user out', function () {
        [$handle] = movedSessionElsewhere($this->user);

        $this->artisan('keyring:sign-out', ['user' => (string) $this->user->id])->assertSuccessful();

        expectEnded($handle, SessionEndReason::SignedOutEverywhere);
        expect($this->announced)->toHaveCount(1);
    });

    it('announces signing everyone out once, and no session by itself', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        sessionElsewhere($this->user);
        $everyone = new Collection;
        Event::listen(fn (EveryoneSignedOut $event) => $everyone->push($event));
        $before = now()->getTimestamp();

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        expect($everyone)->toHaveCount(1)
            ->and($everyone->first()->at)->toBeGreaterThanOrEqual($before)->toBeLessThanOrEqual(now()->getTimestamp())
            ->and($this->announced)->toBeEmpty();
    })->with('session drivers');

    it('announces a revocation of the app\'s own as revoked', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        [$handle, $moved] = movedSessionElsewhere($this->user);

        $revoked = app(SessionRegistry::class)->revoke($moved->id);

        $event = expectEnded($handle, SessionEndReason::Revoked);
        expect($event->endedAt)->toBe($revoked->revokedAt)
            ->and($event->deviceId)->toBeNull();
    })->with('session drivers');
});

describe('what is not an ending', function () {
    it('announces nothing for a record revoked already, moved, or pruned', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $session = sessionElsewhere($this->user);
        $registry->revoke($session->id);
        $this->announced->splice(0);

        expect($registry->revoke($session->id))->toBeNull()
            ->and($registry->revokeAll($this->user))->toBeEmpty();

        moveSession(sessionElsewhere($this->user));
        $registry->prune();

        expect($this->announced)->toBeEmpty();
    })->with('session drivers');

    it('announces nothing for a replaced record revoked by its ID: its session carried on', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $first = sessionElsewhere($this->user);
        moveSession($first);

        expect(app(SessionRegistry::class)->revoke($first->id)?->replacedBy)->not->toBeNull()
            ->and($this->announced)->toBeEmpty();
    })->with('session drivers');

    it('announces nothing when a session moves and the old record is revoked with it', function () {
        $first = sessionElsewhere($this->user);

        app(SessionRegistry::class)->replace($first->id, $first->with(['id' => Str::random(40), 'origin' => $first->id]), revoke: true);

        expect($this->announced)->toBeEmpty();
    });
});

describe('a listener that throws', function () {
    it('still signs the browser out', function () {
        $here = signInHere();
        throwingListener();

        $this->post('/logout')->assertRedirect();

        $this->assertGuest();
        expect(app(SessionRegistry::class)->find($here)->revokedAt)->not->toBeNull()
            ->and($this->announced)->toHaveCount(1);
        Exceptions::assertReported(RuntimeException::class);
    });

    it('still signs out everywhere, and closes the other ways back in', function () {
        signInHere();
        requestEmailChange();
        $this->user->refresh()->forceFill(['remember_token' => 'remembered'])->save();
        $this->user->devices()->update(['trusted_until' => now()->addDay()]);
        $handles = collect([1, 2, 3])->map(fn () => movedSessionElsewhere($this->user)[0]);
        throwingListener();

        expect(app(Sessions::class)->signOutEverywhere($this->user))->toBe(4);

        // Every record is announced, though each announcement threw.
        $handles->each(fn (string $handle) => expectEnded($handle, SessionEndReason::Revoked));
        expect($this->announced)->toHaveCount(4)
            ->and($this->user->fresh()->remember_token)->not->toBe('remembered')
            ->and($this->user->devices()->whereNotNull('trusted_until')->exists())->toBeFalse()
            ->and(PendingChange::sole()->cancelled_at)->not->toBeNull()
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
        Exceptions::assertReportedCount(4);
    });

    it('still deletes what a deleted user had', function () {
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'laptop')]);
        movedSessionElsewhere($this->user);
        throwingListener();

        $this->user->delete();

        expect(Authenticator::count())->toBe(0)
            ->and(Device::count())->toBe(0)
            ->and($this->announced)->toHaveCount(1);
        Exceptions::assertReported(RuntimeException::class);
    });

    it('still locks the account and holds its password after a risk response', function () {
        movedSessionElsewhere($this->user);
        throwingListener();
        Keyring::risk()->respond(fn () => Action::deny()->revokeAllSessions()->lockFor('1h')->requirePasswordChange());

        app(RiskEngine::class)->enforce($this->user, new Risk, Checkpoint::Request);

        expect(app(RiskLocks::class)->locked($this->user))->toBeTrue()
            ->and(app(PasswordHolds::class)->holds($this->user))->toBeTrue()
            ->and($this->announced)->toHaveCount(1);
        Exceptions::assertReported(RuntimeException::class);
    });

    it('still finishes undoing an email change', function () {
        signInHere();
        $tokens = requestEmailChange();
        movedSessionElsewhere($this->user);
        Event::fake([EmailChangeReverted::class]);
        throwingListener();

        expect(app(EmailChanges::class)->revert(PendingChange::sole(), $tokens['revert']))->toBeTrue();

        Event::assertDispatched(EmailChangeReverted::class);
        expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and($this->announced)->toHaveCount(2);
        Exceptions::assertReportedCount(2);
    });

    it('still forgets every device past the limit', function () {
        config(['keyring.devices.limit' => 1]);
        $old = collect(['old', 'older'])->map(fn (string $token, int $age) => $this->user->devices()->forceCreate(['token_hash' => hash('sha256', $token), 'last_seen_at' => now()->subDays($age + 1)]));
        $old->each(fn (Device $device) => movedSessionElsewhere($this->user, $device->id));
        throwingListener();

        signInHere();

        expect(Device::query()->whereKey($old->pluck('id'))->exists())->toBeFalse()
            ->and($this->announced)->toHaveCount(2)
            ->and($this->announced->pluck('reason')->unique()->all())->toBe([SessionEndReason::DeviceLimit]);
        Exceptions::assertReportedCount(2);
    });

    it('still signs everyone out', function () {
        Exceptions::fake();
        Event::listen(fn (EveryoneSignedOut $event) => throw new RuntimeException('A listener failed.'));
        $session = sessionElsewhere($this->user);

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        expect(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
        Exceptions::assertReported(RuntimeException::class);
    });

    it('is not given an event when the session\'s handle can\'t be made, and the session still ends', function () {
        $session = sessionElsewhere($this->user);
        Exceptions::fake();
        config(['app.key' => null]);

        expect(app(SessionRegistry::class)->revoke($session->id)?->revokedAt)->not->toBeNull()
            ->and($this->announced)->toBeEmpty();
        Exceptions::assertReported(MissingAppKeyException::class);
    });
});

describe('when announcements go out', function () {
    it('announces what a sign-out everywhere revokes once its transaction commits', function () {
        $session = sessionElsewhere($this->user);
        $levels = new Collection;
        Event::listen(fn (RegisteredSessionEnded $event) => $levels->push(DB::transactionLevel()));
        $level = DB::transactionLevel();

        DB::transaction(function () {
            app(Sessions::class)->signOutEverywhere($this->user);

            expect($this->announced)->toBeEmpty();
        });

        expect($this->announced)->toHaveCount(1)
            ->and($levels->all())->toBe([$level])
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
    });

    it('announces nothing when the transaction it revoked in is rolled back, as the revocation is', function () {
        $session = sessionElsewhere($this->user);

        expect(fn () => DB::transaction(function (): never {
            app(Sessions::class)->signOutEverywhere($this->user);

            throw new RuntimeException('Something after it failed.');
        }))->toThrow(RuntimeException::class);

        expect($this->announced)->toBeEmpty()
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->toBeNull();
    });

    it('waits for the outermost commit, through savepoints', function () {
        $first = sessionElsewhere($this->user);
        $second = sessionElsewhere($this->user);
        $registry = app(SessionRegistry::class);

        DB::transaction(function () use ($registry, $first, $second) {
            DB::transaction(fn () => $registry->revoke($first->id));

            expect($this->announced)->toBeEmpty();

            // A savepoint rolled back takes its revocation and its announcement with it.
            try {
                DB::transaction(function () use ($registry, $second): never {
                    $registry->revoke($second->id);

                    throw new RuntimeException('Something after it failed.');
                });
            } catch (RuntimeException) {
            }

            expect($this->announced)->toBeEmpty();
        });

        expectEnded(app(Sessions::class)->handle($first), SessionEndReason::Revoked);
        expect($this->announced)->toHaveCount(1)
            ->and($registry->find($second->id)->revokedAt)->toBeNull();
    });

    it('announces nothing a savepoint committed when the transaction around it is rolled back', function () {
        $session = sessionElsewhere($this->user);
        $registry = app(SessionRegistry::class);

        try {
            DB::transaction(function () use ($registry, $session): never {
                DB::transaction(fn () => $registry->revoke($session->id));

                throw new RuntimeException('Something after it failed.');
            });
        } catch (RuntimeException) {
        }

        expect($this->announced)->toBeEmpty()
            ->and($registry->find($session->id)->revokedAt)->toBeNull();
    });

    it('is not put off by a transaction on another connection, nor lost when that one is rolled back', function () {
        $other = registryOnItsOwnConnection();
        config(['keyring.sessions.connection' => null]);
        $session = sessionElsewhere($this->user);

        // Laravel's afterCommit() would wait for the other connection's
        // transaction, the latest one open, and drop this with it.
        DB::transaction(function () use ($other, $session) {
            DB::connection($other)->beginTransaction();
            app(SessionRegistry::class)->revoke($session->id);
            DB::connection($other)->rollBack();

            expect($this->announced)->toBeEmpty();
        });

        expect($this->announced)->toHaveCount(1);
    });

    it('announces straight away with the registry on a connection of its own, though the user\'s transaction is rolled back', function () {
        registryOnItsOwnConnection();
        $session = sessionElsewhere($this->user);

        expect(fn () => DB::transaction(function (): never {
            app(Sessions::class)->signOutEverywhere($this->user);

            expect($this->announced)->toHaveCount(1);

            throw new RuntimeException('Something after it failed.');
        }))->toThrow(RuntimeException::class);

        expect($this->announced)->toHaveCount(1)
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
    });

    it('ties announcements to the registry\'s own connection when it has one', function () {
        $connection = registryOnItsOwnConnection();
        $kept = sessionElsewhere($this->user);
        $dropped = sessionElsewhere($this->user);
        $registry = app(SessionRegistry::class);

        DB::connection($connection)->transaction(fn () => $registry->revoke($kept->id));

        DB::connection($connection)->beginTransaction();
        $registry->revoke($dropped->id);
        DB::connection($connection)->rollBack();

        expect($this->announced)->toHaveCount(1)
            ->and($this->announced->first()->handle)->toBe(app(Sessions::class)->handle($kept))
            ->and($registry->find($dropped->id)->revokedAt)->toBeNull();
    });

    it('announces straight away on the cache driver, whatever happens to a transaction around it', function () {
        config(['keyring.sessions.driver' => 'cache']);
        $session = sessionElsewhere($this->user);

        expect(fn () => DB::transaction(function (): never {
            app(Sessions::class)->signOutEverywhere($this->user);

            throw new RuntimeException('Something after it failed.');
        }))->toThrow(RuntimeException::class);

        expect($this->announced)->toHaveCount(1)
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
    });

    it('still reports a listener that throws once the transaction commits, and announces the rest', function () {
        $sessions = collect([1, 2])->map(fn () => sessionElsewhere($this->user));
        throwingListener();

        DB::transaction(fn () => app(Sessions::class)->signOutEverywhere($this->user));

        expect($this->announced)->toHaveCount(2)
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
        Exceptions::assertReportedCount(2);
    });
});

describe('the event', function () {
    it('never carries the record\'s ID, which is what the "remember me" cookie holds', function () {
        [, $moved] = movedSessionElsewhere($this->user, 'a-device');
        app(SessionRegistry::class)->revoke($moved->id);
        $event = $this->announced->sole();

        expect(serialize($event))->not->toContain($moved->id)->not->toContain($moved->origin)
            ->and(json_encode($event))->not->toContain($moved->id)->not->toContain($moved->origin)
            ->and(unserialize(serialize($event)))->toEqual($event)
            ->and($event->deviceId)->toBe('a-device');
    });

    it('carries the handle under every app key, so a handle kept from before a rotation matches', function () {
        $session = sessionElsewhere($this->user);
        $before = app(Sessions::class)->handle($session);
        config(['app.previous_keys' => [config('app.key')], 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);

        app(SessionRegistry::class)->revoke($session->id);
        $event = $this->announced->sole();

        expect($event->handles)->toBe(app(Sessions::class)->handles($session))
            ->and($event->handles)->toContain($before)
            ->and($event->handle)->not->toBe($before)
            ->and($event->handle)->toBe(app(Sessions::class)->handle($session));
    });
});

describe('the reason', function () {
    it('is plain "revoked" unless the caller says otherwise', function () {
        expect(app(SessionRegistry::class)->reason())->toBe(SessionEndReason::Revoked);
    });

    it('is the innermost one given, and the one before it comes back after', function () {
        $registry = app(SessionRegistry::class);

        $seen = $registry->because(SessionEndReason::Risk, fn () => [
            $registry->reason(),
            $registry->because(SessionEndReason::Idle, fn () => $registry->reason()),
            $registry->reason(),
        ]);

        expect($seen)->toBe([SessionEndReason::Risk, SessionEndReason::Idle, SessionEndReason::Risk])
            ->and($registry->reason())->toBe(SessionEndReason::Revoked);
    });

    it('comes back when the callback throws, so none is left over for whatever runs next', function () {
        $registry = app(SessionRegistry::class);

        expect(fn () => $registry->because(SessionEndReason::Risk, fn () => throw new RuntimeException('Failed.')))->toThrow(RuntimeException::class);

        $session = sessionElsewhere($this->user);
        $registry->revoke($session->id);

        expect($registry->reason())->toBe(SessionEndReason::Revoked)
            ->and($this->announced->sole()->reason)->toBe(SessionEndReason::Revoked);
    });

    it('is what the session was ended for at the time, not when it was announced', function () {
        $session = sessionElsewhere($this->user);
        $registry = app(SessionRegistry::class);

        DB::transaction(fn () => $registry->because(SessionEndReason::Risk, fn () => $registry->revoke($session->id)));

        expect($this->announced->sole()->reason)->toBe(SessionEndReason::Risk);
    });

    it('still runs the callback when the registry bound in its place doesn\'t announce', function () {
        app()->instance(SessionRegistry::class, new CacheSessionRegistry(Cache::store('array')));

        expect(app(Sessions::class)->because(SessionEndReason::Risk, fn () => 'ran'))->toBe('ran');
    });
});

describe('drivers', function () {
    it('wraps Keyring\'s own drivers', function (string $driver, string $class) {
        config(['keyring.sessions.driver' => $driver]);

        expect(app(SessionRegistry::class))->toBeInstanceOf(AnnouncingSessionRegistry::class)
            ->and(app(SessionRegistry::class)->inner())->toBeInstanceOf($class)
            ->and(app(Sessions::class)->registry())->toBe(app(SessionRegistry::class));
    })->with([
        ['database', DatabaseSessionRegistry::class],
        ['cache', CacheSessionRegistry::class],
    ]);

    it('wraps a driver of the app\'s own, and announces what it revokes', function () {
        $custom = new CacheSessionRegistry(Cache::store('array'), 'custom:');
        app(SessionRegistryManager::class)->extend('custom', fn () => $custom);
        config(['keyring.sessions.driver' => 'custom']);
        [$handle, $moved] = movedSessionElsewhere($this->user);

        app(SessionRegistry::class)->revoke($moved->id);

        expect(app(SessionRegistry::class)->inner())->toBe($custom);
        expectEnded($handle, SessionEndReason::Revoked);
    });

    it('doesn\'t wrap a driver twice', function () {
        app(SessionRegistryManager::class)->extend('again', fn () => app(SessionRegistryManager::class)->driver('cache'));
        config(['keyring.sessions.driver' => 'again']);

        expect(app(SessionRegistry::class))->toBe(app(SessionRegistryManager::class)->driver('cache'))
            ->and(app(SessionRegistry::class)->inner())->toBeInstanceOf(CacheSessionRegistry::class);
    });
});

/**
 * The session middleware as an app may extend it, signing out for a
 * reason of its own.
 */
class SignsOutForMaintenance extends AuthenticateSession
{
    public function handle(Request $request, Closure $next): Response
    {
        return $request->is('maintenance') && $this->keyring->guard()->check() ? $this->signOut($request, 'maintenance') : parent::handle($request, $next);
    }
}

/**
 * A user Keyring takes for one being soft deleted.
 */
#[Table(name: 'users')]
class SoftDeletedWithoutSchema extends User
{
    public function isForceDeleting(): bool
    {
        return false;
    }
}

/**
 * Something an app wraps the registry in, as app()->extend() does.
 */
class CountingRegistry implements SessionRegistry
{
    public int $calls = 0;

    public function __construct(private readonly SessionRegistry $registry) {}

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
        $this->calls++;

        return $this->registry->revoke($id);
    }

    public function replace(string $id, RegisteredSession $successor, bool $revoke = false): bool
    {
        return $this->registry->replace($id, $successor, $revoke);
    }

    public function revokeAll(Authenticatable $user, ?string $except = null): Collection
    {
        $this->calls++;

        return $this->registry->revokeAll($user, $except);
    }

    public function revokeDevice(Authenticatable $user, string $deviceId): Collection
    {
        return $this->registry->revokeDevice($user, $deviceId);
    }

    public function revokeEveryone(): void
    {
        $this->registry->revokeEveryone();
    }

    public function prune(): int
    {
        return $this->registry->prune();
    }
}

/**
 * An exception handler that fails as it reports.
 */
function brokenExceptionHandler(): void
{
    app()->instance(ExceptionHandler::class, new class implements ExceptionHandler
    {
        public function report(Throwable $e): void
        {
            throw new LogicException('The exception handler failed too.');
        }

        public function shouldReport(Throwable $e): bool
        {
            return true;
        }

        public function render($request, Throwable $e): never
        {
            throw $e;
        }

        public function renderForConsole($output, Throwable $e): void {}
    });
}

describe('a sign-out that fails part way', function () {
    it('takes a reason of a subclass\'s own, and announces it as revoked', function () {
        app()->bind(AuthenticateSession::class, SignsOutForMaintenance::class);
        Route::middleware(['web', 'auth'])->get('/maintenance', fn () => 'maintenance');
        $handle = handleOf(signInHere());
        $ended = new Collection;
        Event::listen(fn (SessionEnded $event) => $ended->push($event->reason));

        $this->get('/maintenance')->assertRedirect('/login');

        $this->assertGuest();
        expectEnded($handle, SessionEndReason::Revoked);
        expect($ended->all())->toBe(['maintenance']);
    });

    it('still signs out and announces the rest when the exception handler fails too', function () {
        $here = signInHere();
        $handles = collect([1, 2])->map(fn () => movedSessionElsewhere($this->user)[0]);
        Event::listen(fn (RegisteredSessionEnded $event) => throw new RuntimeException('A listener failed.'));
        brokenExceptionHandler();

        expect(app(Sessions::class)->signOutEverywhere($this->user, except: $here))->toBe(2);
        $handles->each(fn (string $handle) => expectEnded($handle, SessionEndReason::Revoked));

        $this->post('/logout')->assertRedirect();

        $this->assertGuest();
        expect($this->announced)->toHaveCount(3);
    });

    it('doesn\'t let a failing exception handler out of the commit', function () {
        sessionElsewhere($this->user);
        sessionElsewhere($this->user);
        Event::listen(fn (RegisteredSessionEnded $event) => throw new RuntimeException('A listener failed.'));
        brokenExceptionHandler();

        DB::transaction(fn () => app(Sessions::class)->signOutEverywhere($this->user));

        expect($this->announced)->toHaveCount(2);
    });

    it('announces everyone signed out when the driver fails after some of its rounds', function () {
        app(SessionRegistryManager::class)->extend('failing-rounds', fn () => new class(DB::connection(), 'keyring_sessions') extends DatabaseSessionRegistry
        {
            public function revokeEveryone(): void
            {
                parent::revokeEveryone();

                throw new RuntimeException('A later round failed.');
            }
        });
        config(['keyring.sessions.driver' => 'failing-rounds']);
        $session = sessionElsewhere($this->user);
        $everyone = new Collection;
        Event::listen(fn (EveryoneSignedOut $event) => $everyone->push($event));

        expect(fn () => app(SessionRegistry::class)->revokeEveryone())->toThrow(RuntimeException::class, 'A later round failed.');

        expect($everyone)->toHaveCount(1)
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
    });

    it('announces what the cache driver revoked before one record failed, then throws the failure', function () {
        $failing = Str::random(40);
        $driver = new class(Cache::store('array'), $failing) extends CacheSessionRegistry
        {
            public function __construct(Repository $cache, private readonly string $failing)
            {
                parent::__construct($cache);
            }

            public function revoke(string $id): ?RegisteredSession
            {
                return $id === $this->failing ? throw new RuntimeException('The store failed.') : parent::revoke($id);
            }
        };
        app(SessionRegistryManager::class)->extend('failing-record', fn () => $driver);
        config(['keyring.sessions.driver' => 'failing-record']);
        $registry = app(SessionRegistry::class);
        $kept = sessionElsewhere($this->user);
        sessionElsewhere($this->user, id: $failing);
        $handles = collect([1, 2])->map(fn () => app(Sessions::class)->handle(sessionElsewhere($this->user)));
        $this->announced->splice(0);

        expect(fn () => $registry->revokeAll($this->user, except: $kept->id))->toThrow(RuntimeException::class, 'The store failed.');

        $handles->each(fn (string $handle) => expectEnded($handle, SessionEndReason::Revoked));
        expect($this->announced)->toHaveCount(2)
            ->and($registry->find($failing)->revokedAt)->toBeNull();

        // The driver on its own says what it revoked, with the failure behind it.
        $partial = null;
        sessionElsewhere($this->user);

        try {
            $driver->revokeAll($this->user, except: $kept->id);
        } catch (PartialRevocation $e) {
            $partial = $e;
        }

        expect($partial?->revoked)->toHaveCount(1)
            ->and($partial?->getPrevious()?->getMessage())->toBe('The store failed.');
    });

    it('keeps a cache revocation, and announces it, when copying it into the record fails', function () {
        $driver = new class(Cache::store('array')) extends CacheSessionRegistry
        {
            protected function stamp(RegisteredSession $session, array $ended): void
            {
                throw new RuntimeException('The store failed.');
            }
        };
        app(SessionRegistryManager::class)->extend('failing-stamp', fn () => $driver);
        config(['keyring.sessions.driver' => 'failing-stamp']);
        $session = sessionElsewhere($this->user);
        Exceptions::fake();

        expect(app(SessionRegistry::class)->revoke($session->id)?->revokedAt)->not->toBeNull()
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
        expectEnded(app(Sessions::class)->handle($session), SessionEndReason::Revoked);
        Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'The store failed.');
    });

    it('still keeps the copy out of the way when even reporting that fails', function () {
        $driver = new class(Cache::store('array')) extends CacheSessionRegistry
        {
            protected function stamp(RegisteredSession $session, array $ended): void
            {
                throw new RuntimeException('The store failed.');
            }
        };
        app(SessionRegistryManager::class)->extend('failing-stamp', fn () => $driver);
        config(['keyring.sessions.driver' => 'failing-stamp']);
        $session = sessionElsewhere($this->user);
        brokenExceptionHandler();

        expect(app(SessionRegistry::class)->revoke($session->id)?->revokedAt)->not->toBeNull()
            ->and($this->announced)->toHaveCount(1);
    });

    it('announces straight away when the transaction can\'t be looked up', function () {
        $session = sessionElsewhere($this->user);
        Exceptions::fake();
        app()->instance('db.transactions', new class extends DatabaseTransactionsManager
        {
            public function callbackApplicableTransactions(): never
            {
                throw new LogicException('Laravel changed.');
            }
        });

        DB::transaction(function () use ($session) {
            app(SessionRegistry::class)->revoke($session->id);

            expect($this->announced)->toHaveCount(1);
        });

        Exceptions::assertReported(LogicException::class);
    });
});

describe('more transactions', function () {
    it('announces everyone signed out once its transaction commits, and not when it is rolled back', function () {
        $session = sessionElsewhere($this->user);
        $registry = app(SessionRegistry::class);
        $everyone = new Collection;
        Event::listen(fn (EveryoneSignedOut $event) => $everyone->push($event));

        try {
            DB::transaction(function () use ($registry): never {
                $registry->revokeEveryone();

                throw new RuntimeException('Something after it failed.');
            });
        } catch (RuntimeException) {
        }

        expect($everyone)->toBeEmpty()
            ->and($registry->find($session->id)->revokedAt)->toBeNull();

        DB::transaction(function () use ($registry, $everyone) {
            $registry->revokeEveryone();

            expect($everyone)->toBeEmpty();
        });

        expect($everyone)->toHaveCount(1)
            ->and($registry->find($session->id)->revokedAt)->not->toBeNull();
    });

    // Laravel runs a commit's callbacks one after another, and stops at the
    // first that throws: the revocation stays and nothing announces it.
    // The sweep a later release adds is what will catch this.
    it('announces nothing when an earlier after-commit callback throws, though the revocation stays', function () {
        $session = sessionElsewhere($this->user);

        expect(fn () => DB::transaction(function () use ($session) {
            DB::afterCommit(fn () => throw new RuntimeException('A queued job could not be pushed.'));
            app(SessionRegistry::class)->revoke($session->id);
        }))->toThrow(RuntimeException::class, 'A queued job could not be pushed.');

        expect($this->announced)->toBeEmpty()
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
    });

    it('announces nothing for a deleted user whose deletion is rolled back', function () {
        $session = sessionElsewhere($this->user);

        expect(fn () => DB::transaction(function (): never {
            $this->user->delete();

            throw new RuntimeException('Something after it failed.');
        }))->toThrow(RuntimeException::class);

        expect($this->announced)->toBeEmpty()
            ->and(User::find($this->user->id))->not->toBeNull()
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->toBeNull();
    });

    it('announces nothing for a soft deleted user whose deletion is rolled back', function () {
        // Taken for soft deleted by Keyring, without a schema change: that
        // would commit the test's own transaction on MySQL.
        $user = SoftDeletedWithoutSchema::findOrFail($this->user->id);
        $session = sessionElsewhere($user);

        expect(fn () => DB::transaction(function () use ($user): never {
            $user->delete();

            throw new RuntimeException('Something after it failed.');
        }))->toThrow(RuntimeException::class);

        expect($this->announced)->toBeEmpty()
            ->and(User::find($user->id))->not->toBeNull()
            ->and(app(SessionRegistry::class)->find($session->id)->revokedAt)->toBeNull();
    });
});

describe('a registry the app wraps', function () {
    it('still announces, with the reason, through a wrapper of the app\'s own', function () {
        $wrappers = new Collection;
        app()->extend(SessionRegistry::class, fn (SessionRegistry $registry) => tap(new CountingRegistry($registry), fn (CountingRegistry $wrapper) => $wrappers->push($wrapper)));
        signInHere();
        [$handle] = movedSessionElsewhere($this->user);

        $this->deleteJson(route('keyring.sessions.destroy-others'))->assertOk();

        expectEnded($handle, SessionEndReason::SignedOutEverywhere);
        expect($wrappers->sum('calls'))->toBeGreaterThan(0)
            ->and(app(SessionRegistry::class))->toBeInstanceOf(CountingRegistry::class);
    });
});

/**
 * The database driver, failing on the given statement: as a missing table
 * would, or as a deadlock does once Laravel has given up on it.
 */
function failingRegistry(int $failOn, bool $deadlock = false, string $id = ''): DatabaseSessionRegistry
{
    return new class(DB::connection(), $failOn, $deadlock, $id) extends DatabaseSessionRegistry
    {
        private int $calls = 0;

        public function __construct(ConnectionInterface $connection, private readonly int $failOn, private readonly bool $deadlock, private readonly string $id)
        {
            parent::__construct($connection);
        }

        protected function query(): Builder
        {
            if (++$this->calls !== $this->failOn) {
                return parent::query();
            }

            if ($this->deadlock) {
                throw new DeadlockException("Deadlock found (SQL: update keyring_sessions where id = {$this->id})", 0, new QueryException('testing', 'update keyring_sessions where id = ?', [$this->id], new PDOException('Deadlock found')));
            }

            return $this->connection->table('keyring_missing');
        }
    };
}

/**
 * Every message an exception and the ones behind it would put in a log.
 */
function messagesOf(Throwable $e): string
{
    $messages = [];

    for (; $e !== null; $e = $e->getPrevious()) {
        $messages[] = $e->getMessage().($e instanceof QueryException ? implode(',', $e->getBindings()) : '');
    }

    return implode("\n", $messages);
}

describe('a database failure', function () {
    it('says what failed without the record IDs it was given', function (Closure $call, int $failOn) {
        $sessions = collect([1, 2, 3])->map(fn () => sessionElsewhere($this->user));
        $failed = null;

        try {
            $call(failingRegistry($failOn), $sessions->first(), $this->user);
        } catch (QueryException $e) {
            $failed = $e;
        }

        expect($failed)->toBeInstanceOf(QueryException::class)
            ->and(messagesOf($failed))->toContain('keyring_missing');
        $sessions->each(fn (RegisteredSession $session) => expect(messagesOf($failed))->not->toContain($session->id));
    })->with([
        'save' => [fn (DatabaseSessionRegistry $registry, RegisteredSession $session) => $registry->save($session), 1],
        'find' => [fn (DatabaseSessionRegistry $registry, RegisteredSession $session) => $registry->find($session->id), 1],
        'update' => [fn (DatabaseSessionRegistry $registry, RegisteredSession $session) => $registry->update($session->id, ['lastActivityAt' => 1]), 1],
        'revoke' => [fn (DatabaseSessionRegistry $registry, RegisteredSession $session) => $registry->revoke($session->id), 1],
        'replace' => [fn (DatabaseSessionRegistry $registry, RegisteredSession $session) => $registry->replace($session->id, $session->with(['id' => Str::random(40)])), 1],
        'revokeAll' => [fn (DatabaseSessionRegistry $registry, RegisteredSession $session, User $user) => $registry->revokeAll($user), 2],
        'revokeEveryone' => [fn (DatabaseSessionRegistry $registry) => $registry->revokeEveryone(), 2],
    ]);

    it('gives up on a deadlock without the record IDs it was given', function () {
        $session = sessionElsewhere($this->user);
        $failed = null;

        try {
            failingRegistry(1, deadlock: true, id: $session->id)->revoke($session->id);
        } catch (DeadlockException $e) {
            $failed = $e;
        }

        expect($failed)->toBeInstanceOf(DeadlockException::class)
            ->and(messagesOf($failed))->toContain('Deadlock found')
            ->not->toContain($session->id);
    });

    it('leaves the failure\'s own words out of a partial revocation', function () {
        $partial = new PartialRevocation(new Collection, new RuntimeException('keyring:sessions:secret-id:revoked'));

        expect($partial->getMessage())->not->toContain('secret-id');
    });
});
