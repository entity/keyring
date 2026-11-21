<?php

declare(strict_types=1);

use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Events\RememberMeReused;
use Keyring\Facades\Keyring;
use Keyring\Models\Device;
use Keyring\Models\SecurityEvent;
use Keyring\Risk\Action;
use Keyring\Risk\RiskLocks;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Support\KeyedHash;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    // These compare what was stored with now(), so the clock only moves
    // when a test moves it.
    $this->freezeSecond();

    $this->user = taylor();
});

/**
 * Sign in with "remember me" ticked, in a browser that wasn't signed in.
 *
 * @return array<string, string>
 */
function rememberedSignIn(string $agent = FIREFOX, string $email = 'taylor@example.com'): array
{
    test()->flushSession();

    return keptCookies(browser(agent: $agent)->post('/login', ['email' => $email, 'password' => 'password', 'remember' => true])->assertRedirect());
}

/**
 * Someone kept a copy of the cookies and sends them later, with no session.
 * They're signed out, and no session is registered for them.
 *
 * @param  array<string, string>  $cookies
 */
function expectKeptCookiesRefused(array $cookies, string $agent = FIREFOX, int $sessionsLeft = 0): void
{
    test()->flushSession();
    browser($cookies, $agent)->get('/home')->assertRedirect('/login');
    test()->assertGuest();

    test()->flushSession();
    browser($cookies, $agent)->getJson('/home')->assertUnauthorized()->assertJsonPath('status', 'signed-out');
    test()->assertGuest();

    expect(app(SessionRegistry::class)->forUser(test()->user))->toHaveCount($sessionsLeft);
}

/**
 * The browser comes back after Laravel's session has gone, with only the
 * cookies it kept.
 *
 * @param  array<string, string>  $cookies
 */
function comeBack(array $cookies, string $agent = FIREFOX, string $ip = '127.0.0.1'): TestResponse
{
    test()->flushSession();

    return browser($cookies, $agent)->withServerVariables(['REMOTE_ADDR' => $ip])->get('/home');
}

/**
 * A request from a browser that still has the session it was given, and
 * the cookies it kept.
 *
 * @param  array<string, mixed>  $session
 * @param  array<string, string>  $cookies
 */
function carryOn(array $session, array $cookies, string $agent = FIREFOX): TestResponse
{
    session()->flush();
    session()->replace($session);

    return browser($cookies, $agent)->get('/home');
}

/**
 * The cookies that hold a session on Laravel's "cookie" session driver.
 *
 * @return array<string, string>
 */
function cookieSession(TestResponse $response): array
{
    $id = $response->getCookie(config('session.cookie'))->getValue();

    return [config('session.cookie') => $id, $id => $response->getCookie($id)->getValue()];
}

/**
 * Every time a used "remember me" cookie ended a session.
 *
 * @return list<RememberMeReused>
 */
function reuses(): array
{
    return test()->reuses->all();
}

function sessionEndedReasons(): array
{
    return SecurityEvent::query()->where('type', 'session_ended')->oldest('id')->get()->map(fn (SecurityEvent $event) => $event->meta['reason'])->all();
}

dataset('session registries', ['database', 'cache']);

it('gives a remembered sign in a cookie naming its session, for as long as the session can last', function () {
    config(['keyring.sessions.absolute' => '7d', 'session.secure' => true]);

    $response = browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
    $cookie = $response->getCookie('__Host-remembered_session');

    expect($cookie->getValue())->toBe(session(Sessions::KEY))
        ->and($cookie->isHttpOnly())->toBeTrue()
        ->and($cookie->isSecure())->toBeTrue()
        ->and($cookie->getSameSite())->toBe('lax')
        ->and($cookie->getExpiresTime())->toBe(now()->addDays(7)->getTimestamp());
});

it('gives a sign in that did not tick "remember me" no such cookie', function () {
    browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect()
        ->assertCookieMissing('remembered_session');
});

it('signs a remembered browser back in under a new record, with the limits its session started with', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.absolute' => '12h']);

    $cookies = rememberedSignIn();
    $old = app(SessionRegistry::class)->find(session(Sessions::KEY));

    // Laravel's own session lasts two hours.
    $this->travel(3)->hours();
    $this->flushSession();

    $response = browser($cookies, CHROME)->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->get('/home')->assertOk();

    $record = app(SessionRegistry::class)->find(session(Sessions::KEY));
    $replaced = app(SessionRegistry::class)->find($old->id);

    // The cookie that came is used up, and the browser has the next one.
    expect($record->id)->not->toBe($old->id)
        ->and($response->getCookie('remembered_session')->getValue())->toBe($record->id)
        ->and($response->getCookie('remembered_session')->getExpiresTime())->toBe($old->expiresAt)
        ->and($replaced->replacedBy)->toBe($record->id)
        ->and($replaced->replacedAt)->toBe(now()->getTimestamp())
        ->and($replaced->isActive(now()->getTimestamp()))->toBeFalse()
        ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);

    // Logged as what it is: a browser signed in again, with nothing proved.
    $entry = SecurityEvent::query()->where('type', 'session_resumed')->sole();

    expect($entry->ip)->toBe('203.0.113.9')
        ->and($entry->device_id)->toBe($record->deviceId)
        ->and(SecurityEvent::query()->where('type', 'signed_in')->count())->toBe(1);

    // It's the same session: when it started and when it ends haven't moved.
    expect($record->authenticatedAt)->toBe($old->authenticatedAt)
        ->and($record->expiresAt)->toBe($old->expiresAt)
        ->and($record->lastActivityAt)->toBe(now()->getTimestamp())
        ->and($record->ip)->toBe('203.0.113.9')
        ->and($record->userAgent)->toBe(CHROME)
        ->and($record->assurance)->toBe(Assurance::None)
        ->and(app(SessionAssurance::class)->level())->toBe(Assurance::None);

    // Coming back didn't start the twelve hours again.
    $this->travelTo(Date::createFromTimestamp($old->expiresAt + 1));
    $this->flushSession();
    browser([...$cookies, ...keptCookies($response)], CHROME)->get('/home')->assertRedirect('/login');
    expect(sessionEndedReasons())->toBe(['expired']);
})->with('session registries');

it('refuses kept "remember me" cookies after the absolute limit ended their session', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.absolute' => '1h']);
    $cookies = rememberedSignIn();

    $this->travel(61)->minutes();

    browser($cookies)->get('/home')
        ->assertRedirect('/login')
        ->assertCookieExpired('remembered_session')
        ->assertCookieExpired(Auth::guard()->getRecallerName());

    expectKeptCookiesRefused($cookies);

    // However long they're kept.
    $this->travel(400)->days();
    expectKeptCookiesRefused($cookies);
})->with('session registries');

it('refuses kept "remember me" cookies after the idle limit ended their session', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.remember_idle' => '10m']);
    $cookies = rememberedSignIn();

    $this->travel(11)->minutes();

    browser($cookies)->get('/home')->assertRedirect('/login')->assertCookieExpired('remembered_session');
    expect(sessionEndedReasons())->toBe(['idle']);

    expectKeptCookiesRefused($cookies);
})->with('session registries');

it('refuses "remember me" cookies whose session passed a limit while the browser was away', function (string $driver, string $limit, int $minutes, array $reasons) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.absolute' => '2h', ...$limit === 'idle' ? ['keyring.sessions.remember_idle' => '10m'] : []]);
    $cookies = rememberedSignIn();

    // No request ever saw the session end, so its record was never revoked.
    $this->flushSession();
    $this->travel($minutes)->minutes();

    expectKeptCookiesRefused($cookies);
    expect(sessionEndedReasons())->toBe($reasons);
})->with('session registries')->with([
    'the absolute limit' => ['absolute', 121, ['expired', 'expired']],
    // Idling out revokes the record, as it does when the session itself is seen to.
    'the idle limit' => ['idle', 11, ['idle', 'revoked']],
]);

it('refuses kept "remember me" cookies after a risk response ended their session', function (string $driver, Action $action) {
    config(['keyring.sessions.driver' => $driver]);
    $cookies = rememberedSignIn();

    Keyring::risk()->signals([SessionFingerprintChanged::class])
        ->respond(fn ($risk) => $risk->isElevated() ? $action : Action::allow());

    // The session turns up in another browser.
    browser($cookies, CHROME)->get('/home')->assertRedirect('/login')->assertCookieExpired('remembered_session');
    expect(sessionEndedReasons())->toBe(['risk']);

    expectKeptCookiesRefused($cookies, CHROME);
})->with('session registries')->with([
    'reauthenticate()' => [fn () => Action::reauthenticate()],
    'deny()' => [fn () => Action::deny()],
]);

it('refuses kept "remember me" cookies after their session was revoked', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    $cookies = rememberedSignIn();

    app(SessionRegistry::class)->revoke(session(Sessions::KEY));

    expectKeptCookiesRefused($cookies);
    expect(sessionEndedReasons())->toBe(['revoked', 'revoked']);
})->with('session registries');

describe('after an administrator signs everyone out', function () {
    it('refuses the "remember me" cookies of a browser that was away', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $cookies = rememberedSignIn();

        $this->travel(1)->hours();
        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        expectKeptCookiesRefused($cookies);
        expect(sessionEndedReasons())->toBe(['revoked', 'revoked']);
    })->with('session registries');

    it('refuses the cookies a browser came back with before, and the ones it was given then', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.remember_grace' => '1h']);
        $cookies = rememberedSignIn();

        $this->travel(3)->hours();
        $resumed = [...$cookies, ...keptCookies(comeBack($cookies)->assertOk())];

        $this->travel(1)->minutes();
        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        // The used cookie, still inside the time it could join the session
        // it was used for, and the one that replaced it.
        expectKeptCookiesRefused($cookies);
        expectKeptCookiesRefused($resumed);

        // Signed out, not taken for a cookie two browsers hold.
        expect(sessionEndedReasons())->toBe(['revoked', 'revoked', 'revoked', 'revoked']);
    })->with('session registries');

    it('signs a browser that is still open out on its next request', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $cookies = rememberedSignIn();
        $session = session()->all();

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        carryOn($session, $cookies)->assertRedirect('/login');
        $this->assertGuest();

        expect(sessionEndedReasons())->toBe(['revoked']);
    })->with('session registries');

    it('lets the same browser sign in again', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        rememberedSignIn();

        $this->artisan('keyring:sign-out', ['--all' => true, '--force' => true])->assertSuccessful();

        $this->travel(1)->seconds();
        $cookies = rememberedSignIn();

        $this->travel(3)->hours();
        comeBack($cookies)->assertOk();
    })->with('session registries');
});

it('refuses a "remember me" cookie that comes without the cookie naming its session', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    $cookies = rememberedSignIn();
    $id = session(Sessions::KEY);

    expectKeptCookiesRefused(Arr::except($cookies, 'remembered_session'), sessionsLeft: 1);

    // The session it was issued with is still there for the browser that has both.
    expect(sessionEndedReasons())->toBe(['expired', 'expired'])
        ->and(app(SessionRegistry::class)->find($id)->revokedAt)->toBeNull();
})->with('session registries');

it('refuses a "remember me" cookie sent with the cookie of someone else\'s session', function () {
    User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    $abigail = rememberedSignIn(email: 'abigail@example.com');
    $hers = session(Sessions::KEY);
    $taylor = rememberedSignIn();

    $this->flushSession();
    browser([...$taylor, 'remembered_session' => $abigail['remembered_session']])->get('/home')->assertRedirect('/login');

    $this->assertGuest();
    expect(sessionEndedReasons())->toBe(['other_user'])
        ->and(app(SessionRegistry::class)->find($hers)->revokedAt)->toBeNull();
});

it('refuses a "remember me" cookie sent with the cookie of another guard\'s session', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    $cookies = rememberedSignIn();

    // Staff sign in to their own guard, and one has the same ID.
    app(SessionRegistry::class)->update(session(Sessions::KEY), ['guard' => 'staff']);

    $this->flushSession();
    browser($cookies)->get('/home')->assertRedirect('/login');

    $this->assertGuest();
})->with('session registries');

it('keeps an app\'s own remembered sign in working after laravel\'s session expires', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    Route::middleware('web')->post('/oauth/callback', fn () => tap('welcome', fn () => Auth::login($this->user, remember: true)));

    $cookies = keptCookies(browser()->post('/oauth/callback')->assertOk());
    $id = session(Sessions::KEY);

    expect($cookies['remembered_session'])->toBe($id);

    $this->flushSession();
    browser($cookies)->get('/home')->assertOk();

    expect(app(SessionRegistry::class)->find($id)->replacedBy)->toBe(session(Sessions::KEY))
        ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
})->with('session registries');

it('gives an app\'s own sign in without "remember me" no cookie naming its session', function () {
    Route::middleware('web')->post('/oauth/callback', fn () => tap('welcome', fn () => Auth::login($this->user)));

    browser()->post('/oauth/callback')->assertOk()->assertCookieMissing('remembered_session');

    expect(session(Sessions::KEY))->not->toBeNull();
});

it('leaves other browsers remembered when one browser\'s session times out', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.remember_idle' => '10m']);

    $firefox = rememberedSignIn(FIREFOX);
    $firefoxSession = session()->all();

    $this->travel(6)->minutes();

    $chrome = rememberedSignIn(CHROME);
    $chromeSession = session()->all();
    $id = session(Sessions::KEY);

    $this->travel(5)->minutes();

    // Firefox has been idle for eleven minutes, Chrome for five.
    session()->flush();
    session()->replace($firefoxSession);
    browser($firefox, FIREFOX)->get('/home')->assertRedirect('/login');
    expect(sessionEndedReasons())->toBe(['idle']);

    session()->flush();
    session()->replace($chromeSession);
    browser($chrome, CHROME)->get('/home')->assertOk();

    // And "remember me" still brings Chrome's session back.
    $this->flushSession();
    browser($chrome, CHROME)->get('/home')->assertOk();

    expect(app(SessionRegistry::class)->find($id)->replacedBy)->toBe(session(Sessions::KEY))
        ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);

    expectKeptCookiesRefused($firefox, FIREFOX, sessionsLeft: 1);
})->with('session registries');

describe('how long a remembered browser may stay away', function () {
    it('is longer than a session nobody asked to be remembered may sit unused', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.idle' => '10m']);

        $cookies = rememberedSignIn();
        expect(app(SessionRegistry::class)->find(session(Sessions::KEY))->remembered)->toBeTrue();

        // Days past the idle limit, and long after Laravel's session went.
        $this->travel(13)->days();
        comeBack($cookies)->assertOk();

        // It's still the remembered session, with nothing proved.
        expect(app(SessionRegistry::class)->find(session(Sessions::KEY))->remembered)->toBeTrue()
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::None)
            ->and(sessionEndedReasons())->toBe([]);
    })->with('session registries');

    it('is two weeks unless the app says otherwise', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        $cookies = rememberedSignIn();

        $this->travel(14)->days();
        $this->travel(1)->minutes();
        comeBack($cookies)->assertRedirect('/login')->assertCookieExpired('remembered_session');

        expect(sessionEndedReasons())->toBe(['idle']);
        expectKeptCookiesRefused($cookies);
    })->with('session registries');

    it('counts from when the browser was last here, not from when it signed in', function () {
        $cookies = rememberedSignIn();

        $this->travel(10)->days();
        $cookies = [...$cookies, ...keptCookies(comeBack($cookies)->assertOk())];

        $this->travel(10)->days();
        comeBack($cookies)->assertOk();
    });

    it('has no limit of its own when the app takes it off', function () {
        config(['keyring.sessions.remember_idle' => null]);

        $cookies = rememberedSignIn();

        $this->travel(29)->days();
        comeBack($cookies)->assertOk();
    });

    it('applies while the remembered session is still open, in place of the idle limit', function () {
        $cookies = rememberedSignIn();
        $session = session()->all();

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);

        // Past the idle limit it stays signed in, with nothing proved any more.
        $this->travel(3)->hours();
        carryOn($session, $cookies)->assertOk();
        $session = session()->all();

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::None);

        $this->travel(14)->days();
        $this->travel(1)->minutes();
        carryOn($session, $cookies)->assertRedirect('/login');

        expect(sessionEndedReasons())->toBe(['idle']);
    });

    it('is not given to a session that did not tick "remember me"', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $session = session()->all();

        expect(app(SessionRegistry::class)->find(session(Sessions::KEY))->remembered)->toBeFalse();

        $this->travel(3)->hours();
        carryOn($session, [])->assertRedirect('/login');

        expect(sessionEndedReasons())->toBe(['idle']);
    })->with('session registries');

    it('stays with a session that is given a new record', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        Keyring::risk()->signals([SessionFingerprintChanged::class]);

        $cookies = rememberedSignIn();
        browser($cookies, CHROME)->get('/home')->assertOk();

        expect(app(SessionRegistry::class)->find(session(Sessions::KEY))->remembered)->toBeTrue();
    })->with('session registries');
});

it('moves "remember me" to the new record when a session is given one', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    Keyring::risk()->signals([SessionFingerprintChanged::class]);

    $cookies = rememberedSignIn();
    $old = session(Sessions::KEY);

    // A step-up answer to the session changing browser swaps its record.
    $response = browser($cookies, CHROME)->get('/home')->assertOk();
    $new = session(Sessions::KEY);

    expect($new)->not->toBe($old)
        ->and($response->getCookie('remembered_session')->getValue())->toBe($new)
        ->and($response->getCookie('remembered_session')->getExpiresTime())->toBe(app(SessionRegistry::class)->find($new)->expiresAt);

    // A copy of the cookie from before names the record that was revoked.
    $this->flushSession();
    browser($cookies, CHROME)->get('/home')->assertRedirect('/login');

    // Nothing happened to the session the browser with the new cookie is on.
    $this->flushSession();
    browser([...$cookies, 'remembered_session' => $new], CHROME)->get('/home')->assertOk();

    expect(app(SessionRegistry::class)->find($new)->replacedBy)->toBe(session(Sessions::KEY))
        ->and(SecurityEvent::query()->where('type', 'remember_me_reused')->exists())->toBeFalse();
})->with('session registries');

describe('a session\'s handle', function () {
    it('stays the same when "remember me" carries the session on, and when a step-up gives it another record', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $sessions = app(Sessions::class);

        $cookies = rememberedSignIn();
        $first = $registry->find(session(Sessions::KEY));
        $handle = $sessions->handle($first);

        // Laravel's own session has gone, and the cookie carries it on.
        $this->travel(3)->hours();
        $response = comeBack($cookies)->assertOk();
        $resumed = $registry->find(session(Sessions::KEY));

        expect($resumed->id)->not->toBe($first->id)
            ->and($resumed->origin)->toBe($first->id)
            ->and($sessions->handle($resumed))->toBe($handle);

        $this->getJson(route('keyring.sessions.index'))->assertJsonCount(1, 'sessions')->assertJsonPath('sessions.0.id', $handle);

        // A step-up answer to the session changing browser swaps its record again.
        Keyring::risk()->signals([SessionFingerprintChanged::class]);
        $response = browser([...$cookies, ...keptCookies($response)], CHROME)->get('/home')->assertOk();
        $stepped = $registry->find(session(Sessions::KEY));

        expect($stepped->id)->not->toBe($resumed->id)
            ->and($stepped->origin)->toBe($first->id)
            ->and($sessions->handle($stepped))->toBe($handle)
            ->and($sessions->find($this->user, $handle)->id)->toBe($stepped->id)
            ->and($sessions->stillSignedIn($this->user, $handle))->toBeTrue();

        // Ended by that handle from another browser, it's the record the
        // session is on now that's revoked, and its browser is signed out.
        $remembered = [...$cookies, ...keptCookies($response)];
        Keyring::risk()->signals([]);
        rememberedSignIn(FIREFOX);

        $this->deleteJson(route('keyring.sessions.destroy', $handle))->assertOk()->assertJsonPath('status', 'session-revoked');

        expect($registry->find($stepped->id)->revokedAt)->not->toBeNull()
            ->and($sessions->stillSignedIn($this->user, $handle))->toBeFalse();

        comeBack($remembered, CHROME)->assertRedirect('/login');
    })->with('session registries');

    it('is still the one a record from before origins were kept had, after the session moves', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $sessions = app(Sessions::class);

        $cookies = rememberedSignIn();
        $id = session(Sessions::KEY);

        // The cache driver's records from then have no origin at all.
        if ($driver === 'cache') {
            Cache::put('keyring:sessions:'.$id, Arr::except(Cache::get('keyring:sessions:'.$id), 'origin'), now()->addDay());
        }

        $old = $registry->find($id);
        $handle = KeyedHash::make(KeyedHash::SESSION_HANDLES, $id);

        expect($old->origin)->toBeNull()
            ->and($sessions->handle($old))->toBe($handle);

        $this->travel(3)->hours();
        comeBack($cookies)->assertOk();
        $resumed = $registry->find(session(Sessions::KEY));

        expect($resumed->id)->not->toBe($id)
            ->and($resumed->origin)->toBe($id)
            ->and($sessions->handle($resumed))->toBe($handle);
    })->with('session registries');
});

it('does not start remembering a session when it is given a new record', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class]);

    browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $old = session(Sessions::KEY);

    browser(agent: CHROME)->get('/home')->assertOk()->assertCookieMissing('remembered_session');

    expect(session(Sessions::KEY))->not->toBe($old);
});

it('clears the cookie naming the session on sign out', function () {
    $cookies = rememberedSignIn();

    browser($cookies)->post('/logout')->assertCookieExpired('remembered_session');
});

describe('a "remember me" cookie first sent to a route without the session middleware', function () {
    beforeEach(function () {
        // It starts the session and checks the guard, but isn't in the "web"
        // group, so Laravel signs the cookie in and Keyring doesn't see it.
        Route::middleware([EncryptCookies::class, AddQueuedCookiesToResponse::class, StartSession::class, 'auth'])
            ->get('/outside', fn () => 'outside');
    });

    it('carries on its session on the next request the middleware sees', function () {
        $cookies = rememberedSignIn();
        $id = session(Sessions::KEY);

        $this->flushSession();
        browser($cookies)->get('/outside')->assertOk();
        expect(session(Sessions::KEY))->toBeNull();

        // The browser now has a signed-in session, and still its cookies.
        browser($cookies)->get('/home')->assertOk()->assertCookie('remembered_session', session(Sessions::KEY));

        expect(app(SessionRegistry::class)->find($id)->replacedBy)->toBe(session(Sessions::KEY))
            ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
    });

    it('is not registered as a new session once its own has ended', function () {
        config(['keyring.sessions.absolute' => '1h']);
        $cookies = rememberedSignIn();

        $this->flushSession();
        $this->travel(61)->minutes();
        browser($cookies)->get('/outside')->assertOk();

        // Whether or not the session it got there comes with the cookies.
        browser()->get('/home')->assertRedirect('/login');

        $this->assertGuest();
        expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty();
    });

    it('leaves a sign in alone when the cookie it came with was refused', function (bool $remember) {
        // The guard tries the cookie when it's asked who is signed in.
        Route::middleware([EncryptCookies::class, AddQueuedCookiesToResponse::class, StartSession::class])
            ->post('/outside/login', fn () => tap('in', fn () => Auth::guest() && Auth::login($this->user, $remember)));

        $cookies = rememberedSignIn();
        app(SessionRegistry::class)->revoke(session(Sessions::KEY));

        // Laravel's cookie stops matching the user, though the guard still
        // says it signed in by the cookie.
        Keyring::withoutProtection(fn () => $this->user->update(['password' => 'another-long-password-1']));

        $this->flushSession();
        browser($cookies)->post('/outside/login')->assertOk();
        expect(Auth::viaRemember())->toBeTrue();

        browser($cookies)->get('/home')->assertOk();

        expect(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
    })->with(['without "remember me"' => false, 'with "remember me"' => true]);

    it('is still refused while the account is risk locked', function () {
        $cookies = rememberedSignIn();
        app(RiskLocks::class)->lock($this->user, 3600);

        $this->flushSession();
        browser($cookies)->get('/outside')->assertOk();
        browser($cookies)->get('/home')->assertRedirect('/login');

        $this->assertGuest();
        expect(sessionEndedReasons())->toBe(['risk']);
    });

    // The cookie is the browser's to send. Another account's value in it is
    // no way to end that account's session.
    it('ends only its own remembered session, whatever the cookie names', function (Closure $keepOut, string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $theirs = rememberedSignIn(email: 'abigail@example.com');
        $mine = rememberedSignIn();
        $keepOut($this->user);

        $this->flushSession();
        browser([...$mine, 'remembered_session' => $theirs['remembered_session']])->get('/home')->assertRedirect('/login');

        expect(app(SessionRegistry::class)->find($theirs['remembered_session'])->revokedAt)->toBeNull()
            ->and(app(SessionRegistry::class)->forUser($abigail))->toHaveCount(1);

        // Its own is still ended when it's the one named.
        $this->flushSession();
        browser($mine)->get('/home')->assertRedirect('/login');

        expect(app(SessionRegistry::class)->find($mine['remembered_session'])->revokedAt)->not->toBeNull();
    })->with([
        'a risk lock' => [fn (User $user) => app(RiskLocks::class)->lock($user, 3600)],
        'the sign-in gate' => [fn (User $user) => Keyring::allowSignInWhen(fn (User $who) => ! $who->is($user))],
    ])->with(['database', 'cache']);

    it('stays refused once the lock is lifted', function () {
        $cookies = rememberedSignIn();
        app(RiskLocks::class)->lock($this->user, 3600);

        $this->flushSession();
        browser($cookies)->get('/outside')->assertOk();
        browser($cookies)->get('/home')->assertRedirect('/login');

        app(RiskLocks::class)->unlock($this->user);

        expectKeptCookiesRefused($cookies);
    });

    it('stays refused once the account is let back in', function () {
        $cookies = rememberedSignIn();
        Keyring::allowSignInWhen(fn () => false);

        $this->flushSession();
        browser($cookies)->get('/outside')->assertOk();
        browser($cookies)->get('/home')->assertRedirect('/login');

        Keyring::allowSignInWhen(fn () => true);

        // Keeping the account out ended everything it had, Laravel's own
        // cookie included, so nothing of Keyring's is even asked.
        $this->flushSession();
        browser($cookies)->get('/home')->assertRedirect('/login');
        $this->assertGuest();

        $this->flushSession();
        browser($cookies)->getJson('/home')->assertUnauthorized();
        $this->assertGuest();

        expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and(sessionEndedReasons())->toBe(['not_allowed']);
    });
});

describe('a "remember me" cookie that has been used', function () {
    beforeEach(function () {
        $this->reuses = collect();

        Event::listen(fn (RememberMeReused $event) => $this->reuses->push($event));
    });

    it('is replaced every time the browser comes back', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);

        $first = rememberedSignIn();
        $second = [...$first, ...keptCookies(comeBack($first)->assertOk())];

        $this->travel(3)->hours();
        $third = [...$second, ...keptCookies(comeBack($second)->assertOk())];

        expect(array_unique([$first['remembered_session'], $second['remembered_session'], $third['remembered_session']]))->toHaveCount(3)
            ->and($registry->find($first['remembered_session'])->replacedBy)->toBe($second['remembered_session'])
            ->and($registry->find($second['remembered_session'])->replacedBy)->toBe($third['remembered_session'])
            ->and(session(Sessions::KEY))->toBe($third['remembered_session'])
            ->and($registry->forUser($this->user))->toHaveCount(1)
            ->and(reuses())->toBeEmpty();
    })->with('session registries');

    it('lets the requests a browser sends together in on one session', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $cookies = rememberedSignIn();

        $first = comeBack($cookies)->assertOk();
        $session = app(SessionRegistry::class)->find(session(Sessions::KEY));

        // Sent with the same cookies, a few seconds behind and by another route.
        $this->travel(9)->seconds();
        $second = comeBack(Arr::except($cookies, 'known_device'), ip: '198.51.100.7')->assertOk();

        // The same session and the same new cookie, not a third.
        expect(session(Sessions::KEY))->toBe($session->id)
            ->and($second->getCookie('remembered_session')->getValue())->toBe($first->getCookie('remembered_session')->getValue())
            ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1)
            ->and(session(Sessions::REMEMBERED))->toBeTrue()
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::None);

        // The record is as the request that resumed it left it, and nothing
        // was recorded for the one that joined.
        expect(app(SessionRegistry::class)->find($session->id))->toEqual($session)
            ->and(Device::count())->toBe(1)
            ->and(sessionEndedReasons())->toBeEmpty()
            ->and(reuses())->toBeEmpty();
    })->with('session registries');

    it('ends the session for both browsers when it is sent again later', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);

        // Another browser of the account stays remembered through all of it.
        $other = rememberedSignIn(CHROME);
        $cookies = rememberedSignIn();
        $token = $this->user->fresh()->remember_token;

        // A copy of the cookies is used first, somewhere else.
        $copy = [...$cookies, ...keptCookies(comeBack($cookies, CHROME, '203.0.113.9')->assertOk())];
        $copySession = session()->all();
        $resumed = $registry->find(session(Sessions::KEY));

        $this->travel(10)->seconds();

        comeBack($cookies)
            ->assertRedirect('/login')
            ->assertCookieExpired('remembered_session')
            ->assertCookieExpired(Auth::guard()->getRecallerName());

        $this->assertGuest();

        // The session the copy was on is gone, and it's on record.
        expect($registry->find($resumed->id)->revokedAt)->toBe(now()->getTimestamp())
            ->and(reuses())->toHaveCount(1)
            ->and(reuses()[0]->user->is($this->user))->toBeTrue()
            ->and(reuses()[0]->session)->toEqual($resumed)
            ->and(sessionEndedReasons())->toBe(['reused']);

        $entry = SecurityEvent::query()->where('type', 'remember_me_reused')->sole();

        expect($entry->authenticatable->is($this->user))->toBeTrue()
            ->and($entry->device_id)->toBe($resumed->deviceId)
            ->and($entry->meta)->toBe(['device' => 'Chrome on macOS'])
            ->and($entry->user_agent)->toBe(FIREFOX);

        // Whoever holds the newer cookie is signed out on their next request.
        carryOn($copySession, $copy, CHROME)->assertRedirect('/login');
        expect(sessionEndedReasons())->toBe(['reused', 'revoked']);

        // Neither set of cookies brings anything back, and it's reported once.
        expectKeptCookiesRefused($cookies, sessionsLeft: 1);
        expectKeptCookiesRefused($copy, CHROME, sessionsLeft: 1);
        expect(reuses())->toHaveCount(1)
            ->and(SecurityEvent::query()->where('type', 'remember_me_reused')->count())->toBe(1);

        // The remember token wasn't changed, so the other browser is still let back.
        expect($this->user->fresh()->remember_token)->toBe($token);
        comeBack($other, CHROME)->assertOk();
    })->with('session registries');

    it('is not let in for longer by being sent again', function () {
        $cookies = rememberedSignIn();

        comeBack($cookies)->assertOk();
        $session = session(Sessions::KEY);

        // Each one lands on the same session, and none of them moves the window.
        foreach (range(1, 3) as $ignored) {
            $this->travel(3)->seconds();
            comeBack($cookies)->assertOk();

            expect(session(Sessions::KEY))->toBe($session);
        }

        $this->travel(1)->seconds();
        comeBack($cookies)->assertRedirect('/login');

        expect(app(SessionRegistry::class)->find($session)->revokedAt)->not->toBeNull()
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and(reuses())->toHaveCount(1);
    });

    it('is not let in from another browser, however soon', function () {
        $cookies = rememberedSignIn();

        comeBack($cookies)->assertOk();
        $session = session(Sessions::KEY);

        comeBack($cookies, CHROME)->assertRedirect('/login');

        expect(app(SessionRegistry::class)->find($session)->revokedAt)->not->toBeNull()
            ->and(reuses())->toHaveCount(1)
            ->and(sessionEndedReasons())->toBe(['reused']);
    });

    it('is refused at once when there is no grace', function (mixed $grace) {
        config(['keyring.sessions.remember_grace' => $grace]);
        $cookies = rememberedSignIn();

        comeBack($cookies)->assertOk();
        comeBack($cookies)->assertRedirect('/login');

        expect(reuses())->toHaveCount(1);
    })->with([0, '0s', null]);

    it('ends the session when a browser is still signed in on the record it replaced', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        // A session turning up in another browser would be signed out for that.
        Keyring::risk()->signals([SessionFingerprintChanged::class])
            ->respond(fn ($risk) => $risk->isElevated() ? Action::reauthenticate() : Action::allow());

        $cookies = rememberedSignIn();
        $session = session()->all();

        // A copy of the cookies is used while the browser they came from is signed in.
        comeBack($cookies, CHROME, '203.0.113.9')->assertOk();
        $resumed = app(SessionRegistry::class)->find(session(Sessions::KEY));

        expect($resumed->userAgent)->toBe(CHROME)
            ->and($resumed->ip)->toBe('203.0.113.9');

        // Its next request is the cookie showing up twice, straight away. It
        // isn't a session that changed browser: the copy's record was never its own.
        carryOn($session, $cookies)->assertRedirect('/login');

        expect(sessionEndedReasons())->toBe(['reused'])
            ->and(SecurityEvent::query()->where('type', 'like', 'risk_%')->exists())->toBeFalse()
            ->and(app(SessionRegistry::class)->find($resumed->id)->revokedAt)->not->toBeNull()
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and(reuses())->toHaveCount(1)
            ->and(reuses()[0]->session)->toEqual($resumed);
    })->with('session registries');

    it('still ends the session after it was given another record', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        Keyring::risk()->signals([SessionFingerprintChanged::class]);

        $cookies = rememberedSignIn();
        $resumed = [...$cookies, ...keptCookies(comeBack($cookies)->assertOk())];

        // A step-up answer to the session changing browser swaps its record.
        $swapped = browser($resumed, CHROME)->get('/home')->assertOk()->getCookie('remembered_session')->getValue();
        expect($swapped)->not->toBe($resumed['remembered_session']);

        $this->travel(1)->minutes();
        comeBack($cookies)->assertRedirect('/login');

        expect(app(SessionRegistry::class)->find($swapped)->revokedAt)->not->toBeNull()
            ->and(reuses())->toHaveCount(1)
            ->and(reuses()[0]->session->id)->toBe($swapped);
    })->with('session registries');

    it('joins the request that used it first when two arrive at the same moment', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);

        $cookies = rememberedSignIn();
        $id = session(Sessions::KEY);
        $winner = null;

        // The address is read while the new record is put together: after
        // this request found the cookie unused, and before it replaces it.
        Keyring::recordIpsUsing(function (Request $request) use ($registry, $id, &$winner) {
            if ($winner === null) {
                $registry->replace($id, $winner = $registry->find($id)->with(['id' => Str::random(40), 'userAgent' => FIREFOX]));
            }

            return $request->ip();
        });

        $response = comeBack($cookies)->assertOk();

        expect(session(Sessions::KEY))->toBe($winner->id)
            ->and($response->getCookie('remembered_session')->getValue())->toBe($winner->id)
            ->and($registry->forUser($this->user))->toHaveCount(1)
            ->and($registry->forUser($this->user)->first()->id)->toBe($winner->id)
            ->and(reuses())->toBeEmpty();
    })->with('session registries');

    it('refuses a cookie naming a record that was never issued', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        $cookies = rememberedSignIn();
        $id = session(Sessions::KEY);

        comeBack([...$cookies, 'remembered_session' => Str::random(40)])->assertRedirect('/login');

        // Nothing is ended for it, and the real cookie still works.
        expect(sessionEndedReasons())->toBe(['expired'])
            ->and(app(SessionRegistry::class)->find($id)->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(reuses())->toBeEmpty();

        comeBack($cookies)->assertOk();
    })->with('session registries');

    it('leaves someone else\'s session alone when sent with their used cookie', function () {
        User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $abigail = rememberedSignIn(email: 'abigail@example.com');
        comeBack($abigail)->assertOk();
        $hers = session(Sessions::KEY);

        $taylor = rememberedSignIn();
        $this->travel(1)->minutes();

        comeBack([...$taylor, 'remembered_session' => $abigail['remembered_session']])->assertRedirect('/login');

        expect(sessionEndedReasons())->toBe(['other_user'])
            ->and(app(SessionRegistry::class)->find($hers)->revokedAt)->toBeNull()
            ->and(reuses())->toBeEmpty();
    });

    it('works the same on the cookie session driver', function (string $driver) {
        config(['session.driver' => 'cookie', 'keyring.sessions.driver' => $driver]);
        app('session')->forgetDrivers();
        app()->forgetInstance('session.store');

        $cookies = keptCookies(browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true])->assertRedirect());
        $id = session(Sessions::KEY);

        // Two requests sent together each get a session cookie of their own,
        // and both hold the same record.
        $first = comeBack($cookies)->assertOk();
        $second = comeBack($cookies)->assertOk();
        $resumed = [...$cookies, ...keptCookies($first)];

        expect($resumed['remembered_session'])->not->toBe($id)
            ->and($second->getCookie('remembered_session')->getValue())->toBe($resumed['remembered_session'])
            ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);

        foreach ([$first, $second] as $response) {
            $this->flushSession();
            browser([...$resumed, ...cookieSession($response)])->get('/home')->assertOk();

            expect(session(Sessions::KEY))->toBe($resumed['remembered_session']);
        }

        // Sent again later, the used cookie ends that session, and a copy of
        // either session cookie goes with it.
        $this->travel(1)->minutes();
        comeBack($cookies)->assertRedirect('/login');

        foreach ([$first, $second] as $response) {
            $this->flushSession();
            browser([...$resumed, ...cookieSession($response)])->get('/home')->assertRedirect('/login');
        }

        expect(reuses())->toHaveCount(1)
            ->and(sessionEndedReasons())->toBe(['reused', 'revoked', 'revoked']);
    })->with('session registries');

    it('keeps the limits of the session through every record', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.remember_idle' => '10m']);

        $cookies = rememberedSignIn();
        $resumed = [...$cookies, ...keptCookies(comeBack($cookies)->assertOk())];

        $this->travel(11)->minutes();
        comeBack($resumed)->assertRedirect('/login');

        expect(sessionEndedReasons())->toBe(['idle'])
            ->and(app(SessionRegistry::class)->find($resumed['remembered_session'])->revokedAt)->not->toBeNull()
            ->and(reuses())->toBeEmpty();
    })->with('session registries');

    it('brings nothing back once the session it became was revoked', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        $cookies = rememberedSignIn();
        $resumed = [...$cookies, ...keptCookies(comeBack($cookies)->assertOk())];

        app(SessionRegistry::class)->revoke($resumed['remembered_session']);

        // Not the new cookie, and not the used one inside its few seconds.
        comeBack($resumed)->assertRedirect('/login');
        comeBack($cookies)->assertRedirect('/login');

        expect(sessionEndedReasons())->toBe(['revoked', 'revoked'])
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and(reuses())->toBeEmpty();
    })->with('session registries');

    it('is no way past a risk lock or the sign-in gate, inside its few seconds', function (Closure $keepOut, string $reason) {
        $cookies = rememberedSignIn();

        comeBack($cookies)->assertOk();
        $keepOut($this->user);

        comeBack($cookies)->assertRedirect('/login');

        // And the session it was used for goes, as one it could still bring back would.
        $this->assertGuest();
        expect(sessionEndedReasons())->toBe([$reason])
            ->and(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
            ->and(reuses())->toBeEmpty();
    })->with([
        'a risk lock' => [fn (User $user) => app(RiskLocks::class)->lock($user, 3600), 'risk'],
        'an account the app keeps out' => [fn () => Keyring::allowSignInWhen(fn () => false), 'not_allowed'],
    ]);
});

describe('replacing a session\'s record', function () {
    beforeEach(function () {
        $this->session = fn (string $id, array $changes = []) => new RegisteredSession($id, (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp())->with($changes);
    });

    it('happens once, and keeps only the record that did it', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $registry->save(($this->session)('old'));

        expect($registry->replace('old', ($this->session)('first')))->toBeTrue()
            ->and($registry->replace('old', ($this->session)('second')))->toBeFalse();

        $old = $registry->find('old');

        expect($old->replacedBy)->toBe('first')
            ->and($old->replacedAt)->toBe(now()->getTimestamp())
            ->and($old->revokedAt)->toBeNull()
            ->and($old->isActive(now()->getTimestamp()))->toBeFalse()
            ->and($registry->find('second'))->toBeNull()
            ->and($registry->forUser($this->user)->map->id->all())->toBe(['first']);
    })->with('session registries');

    it('can revoke the old record in the same step', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $registry->save(($this->session)('old'));

        expect($registry->replace('old', ($this->session)('new'), revoke: true))->toBeTrue()
            ->and($registry->replace('old', ($this->session)('another'), revoke: true))->toBeFalse();

        $old = $registry->find('old');

        expect($old->replacedBy)->toBe('new')
            ->and($old->revokedAt)->toBe(now()->getTimestamp())
            ->and($registry->find('another'))->toBeNull()
            ->and($registry->forUser($this->user)->map->id->all())->toBe(['new']);
    })->with('session registries');

    it('never brings back a record that was revoked', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $registry->save(($this->session)('old'));
        $registry->revoke('old');

        expect($registry->replace('old', ($this->session)('new')))->toBeFalse()
            ->and($registry->replace('old', ($this->session)('new'), revoke: true))->toBeFalse()
            ->and($registry->replace('missing', ($this->session)('new')))->toBeFalse()
            ->and($registry->find('new'))->toBeNull()
            ->and($registry->find('old')->replacedBy)->toBeNull()
            ->and($registry->forUser($this->user))->toBeEmpty();
    })->with('session registries');

    it('is not undone by saving a copy from before, and is not counted as a session', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $registry->save($stale = ($this->session)('old'));
        $registry->replace('old', ($this->session)('new'));

        $registry->save($stale->with(['lastActivityAt' => 5]));
        $registry->update('old', ['lastActivityAt' => 6]);

        expect($registry->find('old')->replacedBy)->toBe('new')
            ->and($registry->forUser($this->user)->map->id->all())->toBe(['new'])
            ->and($registry->revokeAll($this->user))->toBe(1);
    })->with('session registries');

    it('carries a session on from a record once, and tells a request that read it earlier so', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        $registry->save($read = ($this->session)('old'));

        $request = Request::create('/');
        $request->setLaravelSession(app('session.store'));

        $resumed = app(Sessions::class)->resume($request, $this->user, $read);

        expect($resumed->id)->not->toBe('old')
            ->and($resumed->assurance)->toBe(Assurance::None)
            ->and($resumed->expiresAt)->toBe($read->expiresAt)
            ->and(Cookie::queued('remembered_session')->getValue())->toBe($resumed->id);

        // The other request still holds the record as it was.
        expect(app(Sessions::class)->resume($request, $this->user, $read))->toBeNull()
            ->and($request->session()->get(Sessions::KEY))->toBe($resumed->id)
            ->and(Cookie::queued('remembered_session')->getValue())->toBe($resumed->id)
            ->and($registry->forUser($this->user)->map->id->all())->toBe([$resumed->id]);
    })->with('session registries');

    it('keeps the replaced record until it expires, so its cookie is known to be used', function () {
        $registry = app(SessionRegistry::class);
        $registry->save(($this->session)('old'));
        $registry->replace('old', ($this->session)('new'));
        $registry->revoke('new');

        $this->artisan('keyring:prune')->assertSuccessful();

        expect($registry->find('old')->replacedBy)->toBe('new')
            ->and($registry->find('new'))->toBeNull();

        $this->travel(61)->minutes();
        $this->artisan('keyring:prune')->assertSuccessful();

        expect($registry->find('old'))->toBeNull();
    });
});

it('brings nothing back where a session ends with the level it signed in at', function () {
    config(['keyring.sessions.end_on_lapse' => true]);
    $cookies = rememberedSignIn();
    $session = app(SessionRegistry::class)->forUser($this->user)->sole();

    // The cookie proves nothing, so there's no level left to carry on at.
    expectKeptCookiesRefused($cookies);
    expect(app(SessionRegistry::class)->find($session->id)->revokedAt)->not->toBeNull();
});
