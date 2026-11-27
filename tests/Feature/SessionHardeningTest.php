<?php

declare(strict_types=1);

use Illuminate\Auth\AuthenticationException;
use Illuminate\Cache\ApcStore;
use Illuminate\Cache\ApcWrapper;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\Signal;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\Signals\RepeatedFactorFailures;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\DatabaseSessionRegistry;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\SessionRegistryManager;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\SingleSignOn;

class RevokesDuringAssessment implements Signal
{
    public static bool $fired = false;

    public function assess(Assessment $assessment): ?Finding
    {
        if (static::$fired) {
            return null;
        }

        static::$fired = true;
        app(SessionRegistry::class)->revoke($assessment->session->id);

        return new Finding('revoke_once', 60, 'Testing.');
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Request];
    }
}

beforeEach(function () {
    RevokesDuringAssessment::$fired = false;
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    $this->user = taylor();
});

function signInWith(string $agent = FIREFOX): void
{
    test()->withHeader('User-Agent', $agent)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
}

dataset('drivers', ['database', 'cache']);

/**
 * The array driver keeps one store per test, so replaying an old session ID
 * only means something on a driver that reads it back.
 */
function useFileSessions(): void
{
    $directory = sys_get_temp_dir().'/keyring-sessions-'.uniqid();
    mkdir($directory);
    config(['session.driver' => 'file', 'session.files' => $directory]);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');
}

/**
 * Forget what this process holds, then ask for a signed-in page with the
 * given session ID, like another browser would.
 */
function requestWithSessionId(string $id): TestResponse
{
    session()->flush();
    app('auth')->forgetGuards();

    return test()->withCredentials()->withCookie(config('session.cookie'), $id)->getJson(route('keyring.devices.index'));
}

dataset('session rotations', [
    'a password change' => ['putJson', '/user/password', ['current_password' => 'password', 'password' => 'a-brand-new-long-password-1', 'password_confirmation' => 'a-brand-new-long-password-1']],
    'a password change that keeps other sessions' => ['putJson', '/user/password', ['current_password' => 'password', 'password' => 'a-brand-new-long-password-1', 'password_confirmation' => 'a-brand-new-long-password-1', 'sign_out_others' => false]],
    'a step-up' => ['postJson', '/confirm/password', ['password' => 'password']],
    'signing out everywhere else' => ['deleteJson', '/user/devices', []],
    'signing out other sessions' => ['deleteJson', '/user/sessions', []],
]);

it('stops the old session id working after :dataset, and keeps the user signed in', function (string $method, string $uri, array $data) {
    useFileSessions();
    signInWith();
    $this->inertia()->get(route('keyring.confirm.challenge')); // the step-up needs one in progress
    $this->withoutHeader('X-Inertia');

    $old = session()->getId();
    $token = session()->token();
    $registered = session(Sessions::KEY);
    $verified = array_keys(session(SessionAssurance::KEY));
    session()->flash('status', 'kept');

    $this->withCredentials()->withCookie(config('session.cookie'), $old)->{$method}($uri, $data)->assertOk();

    $new = session()->getId();
    expect($new)->not->toBe($old)
        ->and(session()->token())->not->toBe($token)
        ->and(session('status'))->toBe('kept');

    requestWithSessionId($old)->assertUnauthorized();

    requestWithSessionId($new)->assertOk();
    expect(session(Sessions::KEY))->toBe($registered)
        ->and(array_keys(session(SessionAssurance::KEY)))->toBe($verified)
        ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->toBeNull();
})->with('session rotations');

/**
 * The cookies a browser would hold after the response: the session cookie
 * and, on the cookie driver, the one holding the session itself.
 *
 * @return array<string, string>
 */
function sessionCookies(TestResponse $response): array
{
    $id = $response->getCookie(config('session.cookie'))->getValue();

    return [config('session.cookie') => $id, $id => $response->getCookie($id)->getValue()];
}

it('gives a guest\'s cookie session a new id without registering it', function () {
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');
    Route::middleware('web')->post('/rotate', fn (Request $request) => tap(response('rotated'), fn () => app(Sessions::class)->rotate($request)));

    $this->get('/login');
    $before = session()->getId();

    $this->post('/rotate')->assertOk();

    expect(session()->getId())->not->toBe($before)
        ->and(session()->has(Sessions::KEY))->toBeFalse()
        ->and(DB::table('keyring_sessions')->count())->toBe(0);
    $this->assertGuest();
});

it('gives a cookie session a new id without registering it when it has no record, or no one signed in', function () {
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');
    Route::middleware('web')->post('/rotate', fn (Request $request) => tap(response('rotated'), fn () => app(Sessions::class)->rotate($request)));
    Route::middleware('web')->post('/forget-and-rotate', function (Request $request) {
        $request->session()->forget(Sessions::KEY);
        app(Sessions::class)->rotate($request);

        return 'rotated';
    });

    // Signed in, but the session no longer holds its record by the time it rotates.
    $this->actingAs($this->user)->get('/home')->assertOk();
    $registered = session(Sessions::KEY);
    $before = session()->getId();

    $this->post('/forget-and-rotate')->assertOk();

    expect(session()->getId())->not->toBe($before)
        ->and(session()->has(Sessions::KEY))->toBeFalse()
        ->and(DB::table('keyring_sessions')->count())->toBe(1)
        ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->toBeNull();
    $this->assertAuthenticatedAs($this->user);

    // A record, but no one signed in.
    session()->put(Sessions::KEY, $registered);
    app('auth')->forgetGuards();
    $before = session()->getId();

    $this->post('/rotate')->assertOk();

    expect(session()->getId())->not->toBe($before)
        ->and(session(Sessions::KEY))->toBe($registered)
        ->and(DB::table('keyring_sessions')->count())->toBe(1)
        ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->toBeNull();
    $this->assertGuest();
});

it('signs out a copy of a cookie session after :dataset, and keeps the user signed in', function (string $method, string $uri, array $data) {
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');

    $copied = sessionCookies($this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']));
    $registered = session(Sessions::KEY);
    $handle = app(Sessions::class)->handle(app(SessionRegistry::class)->find($registered));

    $current = sessionCookies($this->withCredentials()->withCookies($copied)->{$method}($uri, $data)->assertOk());

    // A new record, but the same session: it keeps its handle.
    expect(session(Sessions::KEY))->not->toBe($registered)
        ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->not->toBeNull()
        ->and(app(Sessions::class)->handle(app(SessionRegistry::class)->find(session(Sessions::KEY))))->toBe($handle)
        ->and(app(Sessions::class)->find($this->user, $handle)->id)->toBe(session(Sessions::KEY));

    session()->flush();
    app('auth')->forgetGuards();
    $this->withCredentials()->withCookies($copied)->getJson(route('keyring.devices.index'))->assertUnauthorized();

    session()->flush();
    app('auth')->forgetGuards();
    $this->withCredentials()->withCookies($current)->getJson(route('keyring.devices.index'))->assertOk();
    expect(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
})->with([
    'a password change' => ['putJson', '/user/password', ['current_password' => 'password', 'password' => 'a-brand-new-long-password-1', 'password_confirmation' => 'a-brand-new-long-password-1']],
    'a password change that keeps other sessions' => ['putJson', '/user/password', ['current_password' => 'password', 'password' => 'a-brand-new-long-password-1', 'password_confirmation' => 'a-brand-new-long-password-1', 'sign_out_others' => false]],
    'signing out everywhere else' => ['deleteJson', '/user/devices', []],
    'signing out other sessions' => ['deleteJson', '/user/sessions', []],
]);

it('signs out a copy of a cookie session from before a step-up, and keeps the user signed in', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');

    $signedIn = sessionCookies($this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']));
    $registered = session(Sessions::KEY);

    // Long enough that the sign in no longer counts as fresh. The step-up needs one in progress.
    $this->travel(16)->minutes();
    $copied = sessionCookies($this->inertia()->withCredentials()->withCookies($signedIn)->get(route('keyring.confirm.challenge'))->assertOk());
    $this->withoutHeader('X-Inertia');

    $current = sessionCookies($this->withCredentials()->withCookies($copied)->postJson('/confirm/password', ['password' => 'password'])->assertOk());

    expect(session(Sessions::KEY))->not->toBe($registered)
        ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->not->toBeNull()
        ->and(app(SessionRegistry::class)->find(session(Sessions::KEY))->authenticatedAt)->toBe(app(SessionRegistry::class)->find($registered)->authenticatedAt);

    // Neither copy from before is a signed-in session any more.
    foreach ([$signedIn, $copied] as $old) {
        session()->flush();
        app('auth')->forgetGuards();
        $this->withCredentials()->withCookies($old)->postJson(route('keyring.authenticators.store', 'totp'))->assertUnauthorized();
    }

    // The browser that stepped up carries on, with what it proved.
    session()->flush();
    app('auth')->forgetGuards();
    $this->withCredentials()->withCookies($current)->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->assertOk();

    expect(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
})->with('drivers');

describe('a browser that signs in while it is signed in', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, Totp::class, SingleSignOn::class]);
        SingleSignOn::$vouchedFor = 'taylor@example.com';

        Route::middleware('web')->post('/sso/callback', fn (Request $request) => Keyring::attempt($request, 'sso'));
    });

    it('signs out a copy of the cookie session it was on', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'session.driver' => 'cookie']);
        app('session')->forgetDrivers();
        app()->forgetInstance('session.store');

        $copied = sessionCookies($this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']));
        $registered = session(Sessions::KEY);

        $current = sessionCookies($this->withCredentials()->withCookies($copied)->post('/sso/callback')->assertRedirect('/dashboard'));

        expect(session(Sessions::KEY))->not->toBe($registered)
            ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->not->toBeNull();

        session()->flush();
        app('auth')->forgetGuards();
        $this->withCredentials()->withCookies($copied)->getJson(route('keyring.devices.index'))->assertUnauthorized();

        session()->flush();
        app('auth')->forgetGuards();
        $this->withCredentials()->withCookies($current)->getJson(route('keyring.devices.index'))->assertOk();
    })->with('drivers');

    it('does not leave the session it was on listed with nobody on it', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        signInWith();
        $registered = session(Sessions::KEY);
        $handle = app(Sessions::class)->handle(app(SessionRegistry::class)->find($registered));

        $this->post('/sso/callback')->assertRedirect('/dashboard');

        // It's a new session, not the old one moved, so it has a handle of its own.
        expect(app(SessionRegistry::class)->forUser($this->user)->map->id->all())->toBe([session(Sessions::KEY)])
            ->and(session(Sessions::KEY))->not->toBe($registered)
            ->and(app(Sessions::class)->handle(app(SessionRegistry::class)->find(session(Sessions::KEY))))->not->toBe($handle)
            ->and(app(Sessions::class)->find($this->user, $handle))->toBeNull()
            ->and(app(Sessions::class)->stillSignedIn($this->user, $handle))->toBeFalse();
    })->with('drivers');
});

it('replaces a planted session id when the password step leaves a pending login', function () {
    useFileSessions();
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->get('/login');
    $planted = session()->getId();

    $this->withCredentials()->withCookie(config('session.cookie'), $planted)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    expect(session()->getId())->not->toBe($planted)
        ->and(session()->has('keyring.attempt.login'))->toBeTrue()
        ->and(session()->getHandler()->read($planted))->toBe('');

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('cancels a pending email change when signing out everywhere else, and from signOutEverywhere', function () {
    Notification::fake();
    signInWith();

    $this->postJson('/user/email', ['email' => 'someone-else@example.com'])->assertOk();
    $change = PendingChange::sole();

    $this->deleteJson(route('keyring.devices.destroy-others'))->assertOk();

    expect($change->fresh()->isPending())->toBeFalse();
    $this->get('/home')->assertOk();

    $this->postJson('/user/email', ['email' => 'someone-else@example.com'])->assertOk();
    $change = PendingChange::query()->whereNull('cancelled_at')->sole();

    app(Sessions::class)->signOutEverywhere($this->user);

    expect($change->fresh()->isPending())->toBeFalse();
});

it('does not let anonymous wrong passwords raise the owner\'s risk', function () {
    Keyring::risk()->signals([RepeatedFactorFailures::class])->respond(fn ($risk) => $risk->has('repeated_failures') ? Action::deny() : Action::allow());
    config(['keyring.limits.per_account' => 100]);

    foreach (range(1, 6) as $guess) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
        $this->travel(15)->seconds();
    }

    $this->travel(5)->minutes();
    signInWith();

    $this->assertAuthenticatedAs($this->user);
});

it('still counts failed second factors after a correct password', function () {
    Keyring::risk()->signals([RepeatedFactorFailures::class])->respond(fn ($risk) => $risk->has('repeated_failures') ? Action::deny() : Action::allow());
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    config(['keyring.limits.per_account' => 100]);

    foreach (range(1, 5) as $guess) {
        signInWith();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);
    }

    signInWith();

    $this->assertGuest();
    expect($this->sessionErrors()->first('email'))->toBe(__('auth.failed'));
});

it('signs out a session whose registry record expired instead of registering it again', function () {
    config(['keyring.sessions.driver' => 'cache', 'keyring.sessions.absolute' => '1h']);
    signInWith();

    $this->travel(62)->minutes();

    $this->get('/home')->assertRedirect('/login');
    $this->assertGuest();
});

it('signs out when ending an expired session fails, and revokes it on the retry without registering it again', function () {
    config(['keyring.sessions.absolute' => '1h']);
    signInWith();
    $registered = session(Sessions::KEY);

    // The registry fails once, as the expired session is being ended.
    app(SessionRegistryManager::class)->extend('flaky', fn () => new class(app('db')->connection(), 'keyring_sessions') extends DatabaseSessionRegistry
    {
        public bool $failed = false;

        public function revoke(string $id): ?RegisteredSession
        {
            if (! $this->failed) {
                $this->failed = true;

                throw new RuntimeException('The database went away.');
            }

            return parent::revoke($id);
        }
    });
    config(['keyring.sessions.driver' => 'flaky']);

    $this->travel(62)->minutes();

    // The browser is signed out whatever the registry does, and the guard's
    // logout, on the way, has a second go at revoking the record.
    $this->get('/home')->assertServerError();
    expect(session(Sessions::KEY))->toBeNull();

    $this->get('/home')->assertRedirect('/login');
    $this->assertGuest();
    expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
        ->and(DB::table('keyring_sessions')->count())->toBe(1)
        ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->not->toBeNull();
});

it('keeps a revoked session revoked after the cache is cleared', function () {
    config(['keyring.sessions.driver' => 'cache']);
    signInWith();

    app(SessionRegistry::class)->revoke(session(Sessions::KEY));
    Cache::flush();

    $this->get('/home')->assertRedirect('/login');
});

// A store that evicts under memory pressure drops keys one at a time. That a
// session ended is kept in its record and in a key beside it, so losing
// either leaves it ended.
it('keeps a session ended when the cache store loses one of the keys that say so', function (string $lost) {
    config(['keyring.sessions.driver' => 'cache']);
    signInWith();
    $registry = app(SessionRegistry::class);
    $id = session(Sessions::KEY);
    $now = now()->getTimestamp();

    $registry->revoke($id);
    $next = new RegisteredSession('next', (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600);
    $registry->save($replaced = $next->with(['id' => 'replaced']));
    $registry->replace('replaced', $next->with(['id' => 'successor']));

    Cache::forget('keyring:sessions:'.$id.$lost);
    Cache::forget('keyring:sessions:replaced'.$lost);

    expect($registry->find($id)->revokedAt)->not->toBeNull()
        ->and($registry->find('replaced')->replacedBy)->toBe('successor')
        ->and($registry->find('replaced')->isActive($now))->toBeFalse()
        // A stale copy saved over the record doesn't undo it either.
        ->and(tap($registry, fn (SessionRegistry $registry) => $registry->save($replaced))->find('replaced')->replacedBy)->toBe('successor');

    $this->get('/home')->assertRedirect('/login');
})->with(['its revoked marker' => ':revoked', 'its replaced marker' => ':replaced']);

// A revoked record saved again (a request updating it as another revokes
// it) puts back the key that says so, should the store have dropped it.
it('keeps a session revoked when its record is saved again after the store lost its revoked marker', function () {
    config(['keyring.sessions.driver' => 'cache']);
    signInWith();
    $registry = app(SessionRegistry::class);
    $id = session(Sessions::KEY);

    $registry->revoke($id);
    Cache::forget('keyring:sessions:'.$id.':revoked');
    $registry->update($id, ['lastActivityAt' => now()->getTimestamp()]);

    expect(Cache::get('keyring:sessions:'.$id.':revoked'))->not->toBeNull()
        ->and($registry->find($id)->revokedAt)->not->toBeNull();

    $this->get('/home')->assertRedirect('/login');
});

// APCu, say, which has no locks: the list of a user's sessions is then
// changed without one.
it('keeps the registry in a cache store that can\'t lock', function () {
    Cache::extend('no-locks', fn () => Cache::repository(new ApcStore(new class extends ApcWrapper
    {
        /** @var array<string, mixed> */
        private array $values = [];

        public function get($key)
        {
            return $this->values[$key] ?? null;
        }

        public function put($key, $value, $seconds)
        {
            $this->values[$key] = $value;

            return true;
        }

        public function delete($key)
        {
            unset($this->values[$key]);

            return true;
        }
    })));
    config(['cache.stores.no-locks' => ['driver' => 'no-locks'], 'keyring.sessions.driver' => 'cache', 'keyring.sessions.store' => 'no-locks']);

    signInWith();
    $first = session(Sessions::KEY);
    $this->post('/logout');
    signInWith(CHROME);
    $registry = app(SessionRegistry::class);

    expect(Cache::store('no-locks')->getStore())->not->toBeInstanceOf(LockProvider::class)
        ->and($registry->forUser($this->user)->map->id->all())->toBe([session(Sessions::KEY)])
        ->and($registry->find($first)->revokedAt)->not->toBeNull();

    $this->get('/home')->assertOk();
});

// A record kept before records said whose table their ID is one of. It can't
// be told from another model's, so its browser signs in again.
it('signs out a session whose cache record is from before records said whose they are', function () {
    config(['keyring.sessions.driver' => 'cache']);
    signInWith();
    $key = 'keyring:sessions:'.session(Sessions::KEY);

    Cache::put($key, Arr::except(Cache::get($key), 'user_type'), 3600);

    $this->get('/home')->assertRedirect('/login');
    $this->assertGuest();
});

// A session with a record that has gone is an ended one, to a request under
// way as it is to the session middleware.
it('refuses a change for a user who has gone by the time it\'s made', function () {
    signInWith();
    $request = request();
    $request->setLaravelSession(session()->driver());

    DB::table('users')->where('id', $this->user->id)->delete();

    expect(fn () => app(Sessions::class)->whileSignedIn($request, $this->user, fn () => 'saved'))
        ->toThrow(AuthenticationException::class);
});

it('refuses a change from a session whose record has gone', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    signInWith();
    $request = request();
    $request->setLaravelSession(session()->driver());
    $change = fn () => app(Sessions::class)->whileSignedIn($request, $this->user, fn () => 'saved');

    expect($change())->toBe('saved');

    $driver === 'database'
        ? DB::table('keyring_sessions')->delete()
        : Cache::forget('keyring:sessions:'.session(Sessions::KEY));

    expect($change)->toThrow(AuthenticationException::class);

    // One Keyring never registered isn't one it keeps track of.
    session()->forget(Sessions::KEY);

    expect($change())->toBe('saved');
})->with('drivers');

it('does not undo a revocation that lands while a request is being assessed', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    Keyring::risk()->signals([new RevokesDuringAssessment]);
    signInWith();

    $this->withHeader('User-Agent', CHROME)->get('/home');

    expect(app(SessionRegistry::class)->find(session(Sessions::KEY))?->revokedAt)->not->toBeNull();
    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');
})->with('drivers');

it('applies lockFor from the request checkpoint too', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class])
        ->respond(fn ($risk) => $risk->isElevated() ? Action::deny()->revokeAllSessions()->lockFor('1h') : Action::allow());

    signInWith();
    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');

    signInWith();
    $this->assertGuest();
});

it('asks again for laravel password confirmation after a mid-session step-up', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class]);
    Route::middleware(['web', 'auth'])->get('/password-confirm', fn () => 'confirm')->name('password.confirm');
    Route::middleware(['web', 'auth', 'password.confirm'])->get('/billing', fn () => 'billing');

    signInWith();
    $this->withHeader('User-Agent', FIREFOX)->get(route('keyring.confirm.challenge'));
    $this->withHeader('User-Agent', FIREFOX)->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);
    $this->withHeader('User-Agent', FIREFOX)->get('/billing')->assertOk();

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertOk();

    $this->withHeader('User-Agent', CHROME)->get('/billing')->assertRedirect('/password-confirm');
});

it('leaves a signed in request without a session alone, as on a stateless api route', function () {
    Route::middleware('keyring.session')->get('/api/ping', fn () => 'pong');

    $this->actingAs($this->user)->get('/api/ping')
        ->assertOk()
        ->assertSee('pong')
        ->assertCookieMissing(config('session.cookie'))
        ->assertCookieMissing('known_device');
});

// A step-up is only forgotten in the copy of the session that saw it. Any
// other copy still holds what was proved, so it has to stop working.
it('signs out a copy of a cookie session from before a mid-session step-up', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class]);
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');

    $copied = sessionCookies($this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']));

    session()->flush();
    app('auth')->forgetGuards();
    $current = sessionCookies($this->withHeader('User-Agent', CHROME)->withCredentials()->withCookies($copied)->get('/home')->assertOk());

    session()->flush();
    app('auth')->forgetGuards();
    $this->withHeader('User-Agent', CHROME)->withCredentials()->withCookies($copied)
        ->postJson(route('keyring.authenticators.store', 'totp'))->assertUnauthorized();

    session()->flush();
    app('auth')->forgetGuards();
    $this->withHeader('User-Agent', CHROME)->withCredentials()->withCookies($current)
        ->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);

    expect(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
});

it('signs out a session whose older copy was saved over a mid-session step-up', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    Keyring::risk()->signals([SessionFingerprintChanged::class]);
    useFileSessions();

    signInWith();
    $id = session()->getId();
    $before = session()->all();

    $this->withHeader('User-Agent', CHROME)->withCredentials()->withCookie(config('session.cookie'), $id)->get('/home')->assertOk();
    expect(session()->has(SessionAssurance::KEY))->toBeFalse();

    // A request that read the session before the step-up finishes after it.
    session()->replace($before);
    session()->save();

    session()->flush();
    app('auth')->forgetGuards();
    $this->withHeader('User-Agent', CHROME)->withCredentials()->withCookie(config('session.cookie'), $id)
        ->postJson(route('keyring.authenticators.store', 'totp'))->assertUnauthorized();
})->with('drivers');

it('answers a signed-out json request with a 401, and remembers where a page visit was going', function () {
    config(['keyring.sessions.driver' => 'cache']);
    signInWith();
    app(SessionRegistry::class)->revoke(session(Sessions::KEY));

    $this->getJson('/home')->assertUnauthorized()->assertJsonPath('status', 'signed-out')->assertJsonPath('page', 'login')->assertJsonPath('redirect', route('login'));

    signInWith();
    app(SessionRegistry::class)->revoke(session(Sessions::KEY));

    $this->get('/home')->assertRedirect('/login');
    expect(session('url.intended'))->toEndWith('/home');
});

describe('a sign-out the app does itself', function () {
    beforeEach(function () {
        Route::middleware('web')->post('/app/logout', function (Request $request) {
            auth()->logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();

            return response()->noContent();
        });

        Route::middleware('web')->post('/app/logout-this-device', function (Request $request) {
            auth()->logoutCurrentDevice();
            $request->session()->invalidate();

            return response()->noContent();
        });

        // The same in the other order, which empties the session before
        // the guard announces the sign-out.
        Route::middleware('web')->post('/app/invalidate-then-logout', function (Request $request) {
            $request->session()->invalidate();
            auth()->logout();

            return response()->noContent();
        });

        Route::middleware('web')->post('/app/invalidate-then-logout-this-device', function (Request $request) {
            $request->session()->invalidate();
            auth()->logoutCurrentDevice();

            return response()->noContent();
        });

        // One that leaves the session as it was, and signs the user back in on it.
        Route::middleware('web')->post('/app/logout-only', fn () => tap(response()->noContent(), fn () => auth()->logout()));
        Route::middleware('web')->post('/app/login', fn () => tap(response()->noContent(), fn () => auth()->login(test()->user)));
    });

    it('ends the session for a copy of its cookie too', function (string $driver, string $uri) {
        config(['keyring.sessions.driver' => $driver, 'session.driver' => 'cookie']);
        app('session')->forgetDrivers();
        app()->forgetInstance('session.store');

        $copied = sessionCookies($this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']));
        $registered = session(Sessions::KEY);

        $this->withCredentials()->withCookies($copied)->post($uri)->assertNoContent();

        expect(app(SessionRegistry::class)->find($registered)->revokedAt)->not->toBeNull()
            ->and(app(Sessions::class)->active($this->user))->toBeEmpty();

        session()->flush();
        app('auth')->forgetGuards();
        $this->withCredentials()->withCookies($copied)->getJson(route('keyring.devices.index'))->assertUnauthorized();
    })->with('drivers')->with(['/app/logout', '/app/logout-this-device', '/app/invalidate-then-logout', '/app/invalidate-then-logout-this-device']);

    it('leaves nothing the session proved for the next sign in on it', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $registered = session(Sessions::KEY);

        expect(session(SessionAssurance::KEY))->not->toBeEmpty();

        $this->post('/app/logout-only')->assertNoContent();

        expect(session(Sessions::KEY))->toBeNull()
            ->and(session(SessionAssurance::KEY))->toBeNull()
            ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->not->toBeNull();

        $this->post('/app/login')->assertNoContent();

        expect(session(Sessions::KEY))->not->toBeNull()->not->toBe($registered)
            ->and(session(SessionAssurance::KEY))->toBeNull()
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::None);
    });

    it('leaves the session alone when another guard signs out', function () {
        config(['auth.guards.staff' => ['driver' => 'session', 'provider' => 'users']]);
        Route::middleware('web')->post('/staff/logout', fn () => tap(response()->noContent(), fn () => auth('staff')->logout()));

        signInWith();
        $registered = session(Sessions::KEY);
        $verified = session(SessionAssurance::KEY);

        $this->post('/staff/logout')->assertNoContent();

        $this->assertAuthenticatedAs($this->user);
        expect(session(Sessions::KEY))->toBe($registered)
            ->and(session(SessionAssurance::KEY))->toBe($verified)
            ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->toBeNull();
        $this->get('/home')->assertOk();
    });

    it('does nothing without a session to end, as in a queued job or a command', function () {
        signInWith();
        $registered = session(Sessions::KEY);

        app()->instance('request', Request::create('/'));
        Auth::guard('web')->logout();

        expect(session(Sessions::KEY))->toBe($registered)
            ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->toBeNull();
    });

    it('still signs out when the registry can\'t be reached, and reports it', function () {
        Exceptions::fake();
        signInWith();
        $registered = session(Sessions::KEY);
        session()->put('auth.password_confirmed_at', now()->getTimestamp());

        app(SessionRegistryManager::class)->extend('unreachable', fn () => new class(app('db')->connection(), 'keyring_sessions') extends DatabaseSessionRegistry
        {
            public function revoke(string $id): never
            {
                throw new RuntimeException('The database went away.');
            }
        });
        $driver = config('keyring.sessions.driver');
        config(['keyring.sessions.driver' => 'unreachable']);

        $this->post('/app/logout-only')->assertNoContent();

        $this->assertGuest();
        expect(session()->has('keyring'))->toBeFalse()
            ->and(session()->has('auth.password_confirmed_at'))->toBeFalse();
        Exceptions::assertReported(fn (RuntimeException $e) => $e->getMessage() === 'The database went away.');

        config(['keyring.sessions.driver' => $driver]);
        expect(app(SessionRegistry::class)->find($registered)->revokedAt)->toBeNull();
    });
});
