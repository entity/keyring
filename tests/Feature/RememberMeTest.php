<?php

use Illuminate\Cookie\Middleware\AddQueuedCookiesToResponse;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Models\SecurityEvent;
use Keyring\Risk\Action;
use Keyring\Risk\RiskLocks;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    $this->user = taylor();
});

/**
 * A request from a browser that holds these cookies and no others. The test
 * client would otherwise send every cookie an earlier request was given, and
 * every response would carry the ones queued for the responses before it.
 *
 * @param  array<string, string>  $cookies
 */
function browser(array $cookies = [], string $agent = FIREFOX): TestCase
{
    Cookie::flushQueuedCookies();
    Auth::forgetGuards();

    return test()->withHeader('User-Agent', $agent)
        ->withCredentials()
        ->withCookies([Auth::guard()->getRecallerName() => '', 'keyring_remember' => '', 'keyring_device' => '', ...$cookies]);
}

/**
 * The long-lived cookies a response left the browser with.
 *
 * @return array<string, string>
 */
function keptCookies(TestResponse $response): array
{
    return collect([Auth::guard()->getRecallerName(), 'keyring_remember', 'keyring_device'])
        ->mapWithKeys(fn (string $name) => [$name => $response->getCookie($name)?->getValue()])
        ->filter()
        ->all();
}

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

function sessionEndedReasons(): array
{
    return SecurityEvent::query()->where('type', 'session_ended')->oldest('id')->get()->map(fn (SecurityEvent $event) => $event->meta['reason'])->all();
}

dataset('session registries', ['database', 'cache']);

it('gives a remembered sign in a cookie naming its session, for as long as the session can last', function () {
    config(['keyring.sessions.absolute' => '7d', 'session.secure' => true]);

    $response = browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
    $cookie = $response->getCookie('keyring_remember');

    expect($cookie->getValue())->toBe(session(Sessions::KEY))
        ->and($cookie->isHttpOnly())->toBeTrue()
        ->and($cookie->isSecure())->toBeTrue()
        ->and($cookie->getSameSite())->toBe('lax')
        ->and($cookie->getExpiresTime())->toBe(now()->addDays(7)->getTimestamp());
});

it('gives a sign in that did not tick "remember me" no such cookie', function () {
    browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect()
        ->assertCookieMissing('keyring_remember');
});

it('signs a remembered browser back in on the same session, with the limits it started with', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.absolute' => '12h']);

    $cookies = rememberedSignIn();
    $id = session(Sessions::KEY);
    $expiresAt = app(SessionRegistry::class)->find($id)->expiresAt;

    // Laravel's own session lasts two hours.
    $this->travel(3)->hours();
    $this->flushSession();

    browser($cookies, CHROME)->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->get('/home')->assertOk();

    $record = app(SessionRegistry::class)->find($id);

    expect(session(Sessions::KEY))->toBe($id)
        ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1)
        ->and($record->expiresAt)->toBe($expiresAt)
        ->and($record->lastActivityAt)->toBe(now()->getTimestamp())
        ->and($record->ip)->toBe('203.0.113.9')
        ->and($record->userAgent)->toBe(CHROME)
        ->and($record->assurance)->toBe(Assurance::None)
        ->and(app(SessionAssurance::class)->level())->toBe(Assurance::None);

    // Coming back didn't start the twelve hours again.
    $this->travelTo(Date::createFromTimestamp($expiresAt + 1));
    browser($cookies, CHROME)->get('/home')->assertRedirect('/login');
    expect(sessionEndedReasons())->toBe(['expired']);
})->with('session registries');

it('refuses kept "remember me" cookies after the absolute limit ended their session', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.absolute' => '1h']);
    $cookies = rememberedSignIn();

    $this->travel(61)->minutes();

    browser($cookies)->get('/home')
        ->assertRedirect('/login')
        ->assertCookieExpired('keyring_remember')
        ->assertCookieExpired(Auth::guard()->getRecallerName());

    expectKeptCookiesRefused($cookies);

    // However long they're kept.
    $this->travel(400)->days();
    expectKeptCookiesRefused($cookies);
})->with('session registries');

it('refuses kept "remember me" cookies after the idle limit ended their session', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.idle' => '10m']);
    $cookies = rememberedSignIn();

    $this->travel(11)->minutes();

    browser($cookies)->get('/home')->assertRedirect('/login')->assertCookieExpired('keyring_remember');
    expect(sessionEndedReasons())->toBe(['idle']);

    expectKeptCookiesRefused($cookies);
})->with('session registries');

it('refuses "remember me" cookies whose session passed a limit while the browser was away', function (string $driver, string $limit, int $minutes, array $reasons) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.absolute' => '2h', ...$limit === 'idle' ? ['keyring.sessions.idle' => '10m'] : []]);
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
    browser($cookies, CHROME)->get('/home')->assertRedirect('/login')->assertCookieExpired('keyring_remember');
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

it('refuses a "remember me" cookie that comes without the cookie naming its session', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    $cookies = rememberedSignIn();
    $id = session(Sessions::KEY);

    expectKeptCookiesRefused(Arr::except($cookies, 'keyring_remember'), sessionsLeft: 1);

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
    browser([...$taylor, 'keyring_remember' => $abigail['keyring_remember']])->get('/home')->assertRedirect('/login');

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

    expect($cookies['keyring_remember'])->toBe($id);

    $this->flushSession();
    browser($cookies)->get('/home')->assertOk();

    expect(session(Sessions::KEY))->toBe($id)
        ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
})->with('session registries');

it('gives an app\'s own sign in without "remember me" no cookie naming its session', function () {
    Route::middleware('web')->post('/oauth/callback', fn () => tap('welcome', fn () => Auth::login($this->user)));

    browser()->post('/oauth/callback')->assertOk()->assertCookieMissing('keyring_remember');

    expect(session(Sessions::KEY))->not->toBeNull();
});

it('leaves other browsers remembered when one browser\'s session times out', function (string $driver) {
    config(['keyring.sessions.driver' => $driver, 'keyring.sessions.idle' => '10m']);

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

    expect(session(Sessions::KEY))->toBe($id)
        ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);

    expectKeptCookiesRefused($firefox, FIREFOX, sessionsLeft: 1);
})->with('session registries');

it('moves "remember me" to the new record when a session is given one', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    Keyring::risk()->signals([SessionFingerprintChanged::class]);

    $cookies = rememberedSignIn();
    $old = session(Sessions::KEY);

    // A step-up answer to the session changing browser swaps its record.
    $response = browser($cookies, CHROME)->get('/home')->assertOk();
    $new = session(Sessions::KEY);

    expect($new)->not->toBe($old)
        ->and($response->getCookie('keyring_remember')->getValue())->toBe($new)
        ->and($response->getCookie('keyring_remember')->getExpiresTime())->toBe(app(SessionRegistry::class)->find($new)->expiresAt);

    // A copy of the cookie from before names the record that was revoked.
    $this->flushSession();
    browser($cookies, CHROME)->get('/home')->assertRedirect('/login');

    $this->flushSession();
    browser([...$cookies, 'keyring_remember' => $new], CHROME)->get('/home')->assertOk();
    expect(session(Sessions::KEY))->toBe($new);
})->with('session registries');

it('does not start remembering a session when it is given a new record', function () {
    Keyring::risk()->signals([SessionFingerprintChanged::class]);

    browser()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $old = session(Sessions::KEY);

    browser(agent: CHROME)->get('/home')->assertOk()->assertCookieMissing('keyring_remember');

    expect(session(Sessions::KEY))->not->toBe($old);
});

it('clears the cookie naming the session on sign out', function () {
    $cookies = rememberedSignIn();

    browser($cookies)->post('/logout')->assertCookieExpired('keyring_remember');
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
        browser($cookies)->get('/home')->assertOk();

        expect(session(Sessions::KEY))->toBe($id)
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

    it('stays refused once the lock is lifted, or the account is let back in', function (Closure $keepOut, Closure $letBack) {
        $cookies = rememberedSignIn();
        $keepOut($this->user);

        $this->flushSession();
        browser($cookies)->get('/outside')->assertOk();
        browser($cookies)->get('/home')->assertRedirect('/login');

        $letBack($this->user);

        expectKeptCookiesRefused($cookies);
    })->with([
        'a risk lock' => [
            fn (User $user) => app(RiskLocks::class)->lock($user, 3600),
            fn (User $user) => app(RiskLocks::class)->unlock($user),
        ],
        'an account the app keeps out' => [
            fn () => Keyring::allowSignInWhen(fn () => false),
            fn () => Keyring::allowSignInWhen(fn () => true),
        ],
    ]);
});
