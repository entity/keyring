<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\Signal;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\PendingChange;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\Signals\RepeatedFactorFailures;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;

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

it('signs out a copy of a cookie session after :dataset, and keeps the user signed in', function (string $method, string $uri, array $data) {
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');

    $copied = sessionCookies($this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']));
    $registered = session(Sessions::KEY);

    $current = sessionCookies($this->withCredentials()->withCookies($copied)->{$method}($uri, $data)->assertOk());

    expect(session(Sessions::KEY))->not->toBe($registered)
        ->and(app(SessionRegistry::class)->find($registered)->revokedAt)->not->toBeNull();

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
]);

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

it('keeps a revoked session revoked after the cache is cleared', function () {
    config(['keyring.sessions.driver' => 'cache']);
    signInWith();

    app(SessionRegistry::class)->revoke(session(Sessions::KEY));
    Cache::flush();

    $this->get('/home')->assertRedirect('/login');
});

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

    $this->getJson('/home')->assertUnauthorized()->assertJsonPath('status', 'signed-out');

    signInWith();
    app(SessionRegistry::class)->revoke(session(Sessions::KEY));

    $this->get('/home')->assertRedirect('/login');
    expect(session('url.intended'))->toEndWith('/home');
});
