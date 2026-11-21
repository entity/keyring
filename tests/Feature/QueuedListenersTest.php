<?php

declare(strict_types=1);

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Queue\Jobs\SyncJob;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\Authenticated;
use Keyring\Events\AuthenticatorRemoved;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Events\RememberMeReused;
use Keyring\Events\SessionResumed;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Risk\Finding;
use Keyring\Risk\Risk;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;

/**
 * A listener the application queues. What it's handed is whatever the
 * event became after a trip through the queue's payload.
 */
final class QueuedKeyringListener implements ShouldQueue
{
    /** @var list<object> */
    public static array $handled = [];

    public function handle(object $event): void
    {
        self::$handled[] = $event;
    }
}

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
    $this->freezeSecond();
    $this->user = taylor();

    // The database queue, so a queued listener's job sits in a table where
    // the test can read what it holds (jobs, a test migration).
    config(['queue.default' => 'database']);
});

/**
 * Sign in with "remember me" ticked, then come back after Laravel's own
 * session has gone, so "remember me" resumes it.
 *
 * @return array{0: array<string, string>, 1: array<string, string>} the cookies from the sign in, and from coming back
 */
function signInAndResume(string $agent = FIREFOX): array
{
    test()->flushSession();
    $signedIn = keptCookies(browser(agent: $agent)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true])->assertRedirect());

    test()->travel(3)->hours();
    test()->flushSession();
    $back = browser($signedIn, $agent)->get('/home')->assertOk();

    return [$signedIn, [...$signedIn, ...keptCookies($back)]];
}

/**
 * The payload of the job queued for an event, as it's stored.
 */
function queuedPayload(string $event): string
{
    $payloads = DB::table('jobs')->pluck('payload')
        ->filter(fn (string $payload) => str_contains(json_decode($payload, true)['data']['command'], $event));

    expect($payloads)->toHaveCount(1);

    return $payloads->sole();
}

/**
 * The serialised job queued for an event, unescaped from the payload's JSON.
 */
function queuedCommand(string $event): string
{
    return json_decode(queuedPayload($event), true)['data']['command'];
}

/**
 * Check a job holds none of the registry IDs there are: every record's own,
 * and the ones it moved to and started on.
 */
function expectNoRegistryIds(string $command): void
{
    $ids = DB::table('keyring_sessions')->get(['id', 'replaced_by', 'origin'])
        ->flatMap(fn (object $row) => [$row->id, $row->replaced_by, $row->origin])
        ->filter()
        ->unique();

    expect($ids)->not->toBeEmpty();

    foreach ($ids as $id) {
        expect($command)->not->toContain($id);
    }
}

/**
 * The event a queue worker hands the listener, once it has run the job.
 *
 * @template T of object
 *
 * @param  class-string<T>  $event
 * @return T
 */
function queuedEvent(string $event): object
{
    QueuedKeyringListener::$handled = [];

    new SyncJob(app(), queuedPayload($event), 'database', 'default')->fire();

    expect(QueuedKeyringListener::$handled)->toHaveCount(1)
        ->and(QueuedKeyringListener::$handled[0])->toBeInstanceOf($event);

    return QueuedKeyringListener::$handled[0];
}

it('queues a resumed session with its handle in place of its registry ID', function () {
    Event::listen(SessionResumed::class, QueuedKeyringListener::class);
    $seen = [];
    Event::listen(function (SessionResumed $event) use (&$seen) {
        $seen[] = $event;
    });

    [$signedIn, $resumed] = signInAndResume();
    $live = $resumed['remembered_session'];
    $record = app(SessionRegistry::class)->find($live);
    $sessions = app(Sessions::class);

    // A listener in the request sees the record as it is.
    expect($seen)->toHaveCount(1)
        ->and($seen[0]->session->id)->toBe($live)
        ->and($seen[0]->handle)->toBe($sessions->handle($record));

    // Neither the live ID nor the one it replaced is anywhere in the job.
    $command = queuedCommand(SessionResumed::class);

    expect($live)->toBe(session(Sessions::KEY))
        ->and($record->origin)->toBe($signedIn['remembered_session'])
        ->and($command)->not->toContain($live)
        ->and($command)->not->toContain($signedIn['remembered_session']);

    expectNoRegistryIds($command);

    // The listener gets the user back, the rest of the record, and a handle
    // that finds the session.
    $event = queuedEvent(SessionResumed::class);

    expect($event->user)->toBeInstanceOf(User::class)
        ->and($event->user->is($this->user))->toBeTrue()
        ->and($event->session)->toEqual($record->withoutIds())
        ->and($event->session->origin)->toBeNull()
        ->and($event->handle)->toBe($sessions->handle($record))
        ->and($sessions->find($event->user, $event->handle))->toEqual($record);
});

it('queues a reused "remember me" cookie\'s ended session with its handle in place of its registry ID', function () {
    Event::listen(RememberMeReused::class, QueuedKeyringListener::class);
    $seen = [];
    Event::listen(function (RememberMeReused $event) use (&$seen) {
        $seen[] = $event;
    });

    // A copy of the cookies is used first, in another browser, then the
    // owner's browser sends them again.
    test()->flushSession();
    $cookies = keptCookies(browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true])->assertRedirect());

    test()->flushSession();
    $copy = keptCookies(browser($cookies, CHROME)->get('/home')->assertOk());
    $ended = session(Sessions::KEY);

    $this->travel(10)->seconds();
    test()->flushSession();
    browser($cookies)->get('/home')->assertRedirect('/login');

    $record = app(SessionRegistry::class)->find($ended);
    $command = queuedCommand(RememberMeReused::class);

    expect($record->revokedAt)->not->toBeNull()
        ->and($seen)->toHaveCount(1)
        ->and($seen[0]->session->id)->toBe($ended)
        ->and($command)->not->toContain($ended)
        ->and($command)->not->toContain($copy['remembered_session'])
        ->and($command)->not->toContain($cookies['remembered_session']);

    expectNoRegistryIds($command);

    // The session has ended, so Sessions::find() no longer leads to it, but
    // the handle is still the one its pages showed.
    $event = queuedEvent(RememberMeReused::class);

    expect($event->user->is($this->user))->toBeTrue()
        ->and($event->session)->toEqual($seen[0]->session->withoutIds())
        ->and($event->handle)->toBe($seen[0]->handle)
        ->and($event->handle)->toBe(app(Sessions::class)->handle($record));
});

it('queues an ended session by its handle, without any of its registry IDs', function () {
    Event::listen(RegisteredSessionEnded::class, QueuedKeyringListener::class);
    $seen = [];
    Event::listen(function (RegisteredSessionEnded $event) use (&$seen) {
        $seen[] = $event;
    });

    // A session "remember me" carried on, so its record has one it replaced
    // and one it started on.
    [$signedIn, $resumed] = signInAndResume();
    $record = app(SessionRegistry::class)->find($resumed['remembered_session']);

    browser($resumed)->post('/logout')->assertRedirect();

    $command = queuedCommand(RegisteredSessionEnded::class);

    expect($seen)->toHaveCount(1)
        ->and($command)->not->toContain($record->id)
        ->and($command)->not->toContain($signedIn['remembered_session']);

    expectNoRegistryIds($command);

    $event = queuedEvent(RegisteredSessionEnded::class);

    expect($event)->toEqual($seen[0])
        ->and($event->handle)->toBe(app(Sessions::class)->handle($record))
        ->and($event->reason)->toBe(SessionEndReason::LoggedOut);
});

dataset('session events', [
    'SessionResumed' => [SessionResumed::class],
    'RememberMeReused' => [RememberMeReused::class],
]);

it('works out the handle of a session event made without one, from the full record', function (string $class) {
    $record = new RegisteredSession(
        id: str_repeat('a', 40), userId: (string) $this->user->id, userType: RegisteredSession::typeOf($this->user), guard: 'web',
        deviceId: null, assurance: Assurance::None, ip: null, userAgent: null,
        authenticatedAt: 0, lastActivityAt: 0, expiresAt: 0, replacedBy: str_repeat('b', 40), origin: str_repeat('c', 40),
    );
    $handle = app(Sessions::class)->handle($record);

    $event = new $class($this->user, $record);
    $serialised = serialize($event);
    $copy = unserialize($serialised);

    // In the request, the event has the record as it is and its handle.
    expect($event->session)->toBe($record)
        ->and($event->handle)->toBe($handle);

    // Queued, none of the record's IDs go with it, but the handle does.
    expect($serialised)->not->toContain(str_repeat('a', 40))->not->toContain(str_repeat('b', 40))->not->toContain(str_repeat('c', 40))
        ->and($copy->session)->toEqual($record->withoutIds())
        ->and($copy->session->id)->toBe('')
        ->and($copy->session->replacedBy)->toBeNull()
        ->and($copy->session->origin)->toBeNull()
        ->and($copy->handle)->toBe($handle);

    // A handle the dispatcher passes is the one the event keeps.
    expect(unserialize(serialize(new $class($this->user, $record, 'given')))->handle)->toBe('given');
})->with('session events');

it('gives no handle for a record without its IDs', function () {
    $record = new RegisteredSession(
        id: str_repeat('a', 40), userId: (string) $this->user->id, userType: RegisteredSession::typeOf($this->user), guard: 'web',
        deviceId: null, assurance: Assurance::None, ip: null, userAgent: null,
        authenticatedAt: 0, lastActivityAt: 0, expiresAt: 0, origin: str_repeat('c', 40),
    );

    expect(fn () => app(Sessions::class)->handle($record->withoutIds()))->toThrow(LogicException::class)
        ->and(fn () => app(Sessions::class)->handles($record->withoutIds()))->toThrow(LogicException::class);
});

it('queues a sign in without the user\'s password hash or remember token', function () {
    Event::listen(Authenticated::class, QueuedKeyringListener::class);

    test()->flushSession();
    browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true])->assertRedirect();

    $user = $this->user->fresh();
    $command = queuedCommand(Authenticated::class);

    expect($user->remember_token)->not->toBeEmpty()
        ->and($command)->not->toContain($user->getAuthPassword())
        ->and($command)->not->toContain($user->remember_token);

    // The attempt looks its user up again when it's asked for.
    $event = queuedEvent(Authenticated::class);

    expect($event->user->is($user))->toBeTrue()
        ->and($event->attempt->purpose)->toBe(Purpose::Login)
        ->and($event->attempt->user()->is($user))->toBeTrue()
        ->and($event->attempt->keyring()->all()->pluck('factor')->all())->toContain('password');
});

it('serialises an attempt as the same plain data it keeps in the session', function () {
    $user = $this->user->fresh();
    $totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
    $attempt = Attempt::start(Purpose::Confirm, $user, remember: true, requirement: Requirement::aal2(), verifications: [
        new Verification(factor: 'password', authenticator: null, categories: [Category::Knowledge], at: now()->getTimestamp()),
    ]);
    $attempt->record(Verification::of($totp));
    $attempt->present($totp);
    $attempt->put('webauthn', 'options', '{}');
    $attempt->resolveDevice('device-1');
    $attempt->risk = new Risk([new Finding('new_device', 20, 'A device the account has not used.')]);
    $attempt->trustDevice = true;
    $attempt->stepUp = true;
    $attempt->exhausted = true;
    $attempt->keyring();

    $serialised = serialize($attempt);
    $copy = unserialize($serialised);

    expect($serialised)->not->toContain($user->getAuthPassword())
        ->and($copy->toArray())->toBe($attempt->toArray())
        ->and($copy->verifications)->toEqual($attempt->verifications)
        ->and($copy->requirement)->toEqual($attempt->requirement)
        ->and($copy->risk)->toEqual($attempt->risk)
        ->and($copy->complete)->toBeTrue()
        ->and($copy->presented('totp'))->toBe($totp->id)
        ->and($copy->user()->is($user))->toBeTrue()
        ->and($copy->user())->not->toBe($user);
});

/**
 * An attempt serialised as 0.2 and earlier serialised it. They had no
 * __serialize(), so PHP stored the object's own properties, private ones
 * under their mangled names, the same as an array cast gives. The names
 * are checked against 0.2's, so this notices if the properties change.
 */
function serialisedByOldVersion(Attempt $attempt): string
{
    $properties = (array) $attempt;
    $private = fn (string $name) => "\0".Attempt::class."\0".$name;

    expect(array_keys($properties))->toEqualCanonicalizing([
        'id', 'purpose', 'guard', 'userId', 'expiresAt', 'remember', 'verifications', 'requirement', 'state', 'presented',
        $private('resolvedUser'), $private('resolvedKeyring'), 'trustDevice', 'deviceId', 'deviceResolved', 'risk', 'stepUp', 'exhausted',
    ])->and($properties['purpose'])->toBeInstanceOf(Purpose::class);

    return preg_replace('/^a:(\d+):/', 'O:'.strlen(Attempt::class).':"'.Attempt::class.'":$1:', serialize($properties));
}

/**
 * A sign in waiting on its last step, with the user it looked up cached.
 */
function attemptWithEverything(User $user): Attempt
{
    $totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
    $attempt = Attempt::start(Purpose::Login, $user, remember: true, requirement: Requirement::aal2(), verifications: [
        new Verification(factor: 'password', authenticator: null, categories: [Category::Knowledge], at: now()->getTimestamp()),
    ]);
    $attempt->record(Verification::of($totp));
    $attempt->present($totp);
    $attempt->resolveDevice('device-1');
    $attempt->risk = new Risk([new Finding('new_device', 20, 'A device the account has not used.')]);
    $attempt->trustDevice = true;
    $attempt->stepUp = true;

    return $attempt;
}

it('restores a job queued by 0.2 for an event with an attempt, and looks the user up again', function () {
    Event::listen(Authenticated::class, QueuedKeyringListener::class);

    // Nothing in it is serialised twice, so the old attempt has no
    // back-references and can be swapped into a job of this version's.
    $user = $this->user->fresh();
    $attempt = Attempt::start(Purpose::Login, $user, remember: true, verifications: [
        new Verification(factor: 'password', authenticator: null, categories: [Category::Knowledge], at: now()->getTimestamp()),
    ]);
    $attempt->resolveDevice('device-1');
    $old = serialisedByOldVersion($attempt);

    expect($old)->toContain($user->getAuthPassword());

    // Queue the event as this version does, then swap the attempt in the
    // job for the one 0.2 would have queued.
    Authenticated::dispatch($user, $attempt);

    $job = DB::table('jobs')->sole();
    $payload = json_decode($job->payload, true);
    $new = serialize($attempt);

    expect(substr_count($payload['data']['command'], $new))->toBe(1);

    $payload['data']['command'] = str_replace($new, $old, $payload['data']['command']);
    DB::table('jobs')->where('id', $job->id)->update(['payload' => json_encode($payload)]);

    // The user it had cached is dropped, so the attempt finds the user as
    // the database has it now.
    $user->update(['name' => 'Taylor Otwell']);

    $event = queuedEvent(Authenticated::class);

    expect($event->attempt->toArray())->toBe($attempt->toArray())
        ->and($event->user->is($user))->toBeTrue()
        ->and($event->attempt->user()->is($user))->toBeTrue()
        ->and($event->attempt->user()->name)->toBe('Taylor Otwell');
});

it('restores an attempt serialised by 0.2 with its keyring looked up, and looks both up again', function () {
    $user = $this->user->fresh();
    $attempt = attemptWithEverything($user);
    $attempt->keyring();

    // The cached keyring holds the user again, so this is unserialised on
    // its own: its back-references only hold in a stream of its own.
    $old = serialisedByOldVersion($attempt);
    $user->update(['name' => 'Taylor Otwell']);
    $copy = unserialize($old);

    expect($copy->toArray())->toBe($attempt->toArray())
        ->and($copy->complete)->toBeTrue()
        ->and($copy->user()->is($user))->toBeTrue()
        ->and($copy->user()->name)->toBe('Taylor Otwell')
        ->and($copy->keyring()->user->name)->toBe('Taylor Otwell')
        ->and($copy->keyring()->all()->pluck('factor')->all())->toContain('totp');
});

it('queues a removed authenticator without its secret or the user\'s password hash', function () {
    Event::listen(AuthenticatorRemoved::class, QueuedKeyringListener::class);

    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $secret = $totp->secret;
    $stored = $totp->getAttributes()['secret'];
    $totp->load('authenticatable');
    $totp->delete();

    AuthenticatorRemoved::dispatch($this->user, $totp);

    $command = queuedCommand(AuthenticatorRemoved::class);

    expect($command)->not->toContain($stored)
        ->and($command)->not->toContain($secret)
        ->and($command)->not->toContain($this->user->getAuthPassword());

    // The user comes back from the database. The authenticator is deleted,
    // so it comes as it was, less its secret.
    $event = queuedEvent(AuthenticatorRemoved::class);

    expect($event->user->is($this->user))->toBeTrue()
        ->and($event->authenticator->id)->toBe($totp->id)
        ->and($event->authenticator->name)->toBe($totp->name)
        ->and($event->authenticator->factor)->toBe('totp')
        ->and($event->authenticator->secret)->toBeNull()
        ->and($event->authenticator->relationLoaded('authenticatable'))->toBeFalse()
        ->and($totp->secret)->toBe($secret);
});

it('queues a removed authenticator without a secret it saved before it was deleted', function () {
    Event::listen(AuthenticatorRemoved::class, QueuedKeyringListener::class);

    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $before = $totp->getAttributes()['secret'];

    // The same instance has its secret changed and saved, then is deleted,
    // so Eloquent still remembers both values on it.
    $totp->secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
    $totp->save();
    $after = $totp->getAttributes()['secret'];
    $totp->delete();

    AuthenticatorRemoved::dispatch($this->user, $totp);

    $command = queuedCommand(AuthenticatorRemoved::class);

    expect($before)->not->toBe($after)
        ->and($command)->not->toContain($before)
        ->and($command)->not->toContain($after)
        ->and($command)->not->toContain('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP');

    $event = queuedEvent(AuthenticatorRemoved::class);

    expect($event->authenticator->id)->toBe($totp->id)
        ->and($event->authenticator->exists)->toBeFalse()
        ->and($event->authenticator->getChanges())->toBe([])
        ->and($event->authenticator->getOriginal())->not->toHaveKey('secret');
});
