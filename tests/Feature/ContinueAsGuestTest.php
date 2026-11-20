<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Events\SessionEnded;
use Keyring\Facades\Keyring;
use Keyring\Risk\Action;
use Keyring\Risk\RiskLocks;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    $page = fn () => Auth::check() ? 'signed in' : 'guest';

    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home')->name('home');
    Route::middleware('web')->get('/welcome', $page)->name('welcome');
    Route::middleware('web')->post('/welcome', $page)->name('welcome.store');
    Route::middleware('web')->get('/docs/{page}', $page)->name('docs.show');
    Route::middleware('web')->get('/pricing', $page)->name('pricing');
    Route::middleware('web')->get('/unnamed', $page);
    Route::middleware(['web', 'auth'])->get('/account', $page)->name('account');

    config(['keyring.sessions.continue_as_guest' => ['welcome', 'welcome.store', 'docs.*', 'unnamed', 'account']]);

    $this->freezeSecond();
    $this->user = taylor();
    $this->ended = collect();

    Event::listen(fn (SessionEnded $event) => $this->ended->push($event->reason));
});

/**
 * The reason SessionEnded gives for each way a session ends here.
 */
function endedReason(string $case): string
{
    return match ($case) {
        'lapsed' => 'idle',
        'locked' => 'risk',
        default => $case,
    };
}

/**
 * Sign in, then end the session for the given reason before the next request.
 *
 * Returns the cookies the next request should send, for the reasons that
 * need a browser holding its "remember me" cookies.
 *
 * @return array<string, string>
 */
function endSessionFor(string $reason): array
{
    $sign = fn (bool $remember = false) => test()->withHeader('User-Agent', FIREFOX)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => $remember]);

    // A risk lock refuses the cookie when the browser comes back.
    if ($reason === 'locked') {
        test()->flushSession();
        $cookies = guestCookies($sign(true));

        app(RiskLocks::class)->lock(test()->user, 3600);
        test()->flushSession();

        return $cookies;
    }

    if ($reason === 'reused') {
        test()->flushSession();
        $cookies = guestCookies($sign(true));

        // The cookies are used once, then sent again past the grace period.
        test()->flushSession();
        rememberedBrowser($cookies)->get('/home')->assertOk();
        test()->travel(11)->seconds();
        test()->flushSession();

        return $cookies;
    }

    if ($reason === 'expired') {
        config(['keyring.sessions.absolute' => '1h']);
    }

    // The level it signed in at runs out before the session's own idle limit.
    if ($reason === 'lapsed') {
        config(['keyring.sessions.end_on_lapse' => true, 'keyring.sessions.levels.aal1' => ['idle' => '30m', 'absolute' => '30d']]);
    }

    $sign();

    match ($reason) {
        'revoked' => app(SessionRegistry::class)->revoke(session(Sessions::KEY)),
        'expired' => test()->travel(62)->minutes(),
        'idle' => test()->travel(3)->hours(),
        'lapsed' => test()->travel(31)->minutes(),
        'other_user' => test()->actingAs(staff()),
        'not_allowed' => Keyring::allowSignInWhen(fn (User $user) => false),
        'risk' => Keyring::risk()->signals([SessionFingerprintChanged::class])
            ->respond(fn ($risk) => $risk->isElevated() ? Action::deny() : Action::allow()),
    };

    return [];
}

/**
 * The long-lived cookies a response left the browser with.
 *
 * @return array<string, string>
 */
function guestCookies(TestResponse $response): array
{
    return collect([Auth::guard()->getRecallerName(), 'remembered_session'])
        ->mapWithKeys(fn (string $name) => [$name => (string) $response->getCookie($name)?->getValue()])
        ->all();
}

/**
 * The cookies a browser holds after this response: what it held before,
 * with the ones the response set replaced and the ones it cleared gone.
 *
 * @param  array<string, string>  $held
 * @return array<string, string>
 */
function cookiesAfter(TestResponse $response, array $held = []): array
{
    foreach ($response->headers->getCookies() as $cookie) {
        unset($held[$cookie->getName()]);

        if (! $cookie->isCleared()) {
            $held[$cookie->getName()] = (string) $response->getCookie($cookie->getName())->getValue();
        }
    }

    return $held;
}

/**
 * A request from a browser holding these cookies and no session.
 *
 * @param  array<string, string>  $cookies
 */
function rememberedBrowser(array $cookies): mixed
{
    Cookie::flushQueuedCookies();
    Auth::forgetGuards();

    return test()->withHeader('User-Agent', FIREFOX)->withCredentials()->withOnlyCookies($cookies);
}

/**
 * The page visit that finds the session over, from the browser it ended in.
 *
 * @param  array<string, string>  $cookies
 */
function visitAfterEnding(string $reason, array $cookies, string $uri, array $headers = []): TestResponse
{
    $agent = $reason === 'risk' ? CHROME : FIREFOX;

    return ($cookies === [] ? test()->withHeader('User-Agent', $agent) : rememberedBrowser($cookies))
        ->withHeaders($headers)
        ->get($uri);
}

dataset('reasons', ['revoked', 'expired', 'idle', 'lapsed', 'other_user', 'not_allowed', 'risk', 'locked', 'reused']);

// Someone else may hold the session, so its owner hears about it.
dataset('security reasons', ['risk', 'locked', 'reused']);

/**
 * The headers an Inertia visit sends.
 *
 * @return array<string, string>
 */
function inertiaVisit(): array
{
    return ['X-Inertia' => 'true', 'X-Requested-With' => 'XMLHttpRequest', 'Accept' => 'text/html, application/xhtml+xml'];
}

it('asks for a listed page again as a guest when the session ended as :dataset', function (string $reason) {
    $cookies = endSessionFor($reason);

    $response = visitAfterEnding($reason, $cookies, '/welcome?b=2&a=1')
        ->assertRedirect('/welcome?a=1&b=2')
        ->assertHeader('Clear-Site-Data', '"cache", "storage"')
        ->assertSessionMissing('status');

    $this->assertGuest();
    expect(session()->has('url.intended'))->toBeFalse()
        ->and($this->ended->all())->toBe([endedReason($reason)]);

    // The browser is left with no session to carry on and no cookie to
    // bring one back, so following the redirect lands as a guest, once.
    if ($cookies !== []) {
        $response->assertCookieExpired(Auth::guard()->getRecallerName())->assertCookieExpired('remembered_session');
        $cookies = guestCookies($response);
    }

    visitAfterEnding($reason, $cookies, $response->headers->get('Location'))->assertOk()->assertSee('guest');

    $this->assertGuest();
    expect($this->ended->all())->toBe([endedReason($reason)]);
})->with(['revoked', 'expired', 'idle', 'lapsed', 'other_user', 'not_allowed']);

it('sends a listed page to log in as before when the session ended as :dataset on :dataset', function (string $reason, array $headers) {
    $cookies = endSessionFor($reason);

    $response = visitAfterEnding($reason, $cookies, '/welcome?b=2&a=1', $headers)
        ->assertRedirect('/login')
        ->assertHeader('Clear-Site-Data', '"cache", "storage"')
        ->assertHeaderMissing('X-Inertia-Location')
        ->assertSessionHas('status', 'signed-out');

    if ($cookies !== []) {
        $response->assertCookieExpired(Auth::guard()->getRecallerName())->assertCookieExpired('remembered_session');
    }

    $this->assertGuest();
    expect(session('url.intended'))->toEndWith('/welcome?a=1&b=2')
        ->and($this->ended->all())->toBe([endedReason($reason)]);
})->with('security reasons')->with([
    'a page visit' => [[]],
    'an inertia visit' => [inertiaVisit()],
]);

it('sends an unlisted page to log in as before when the session ended as :dataset', function (string $reason) {
    $cookies = endSessionFor($reason);

    visitAfterEnding($reason, $cookies, '/pricing')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

    expect(session('url.intended'))->toEndWith('/pricing')
        ->and($this->ended->all())->toBe([endedReason($reason)]);
})->with('reasons');

it('matches route names with wildcards', function () {
    endSessionFor('revoked');

    $this->get('/docs/install')->assertRedirect('/docs/install');
    $this->get('/docs/install')->assertOk()->assertSee('guest');

    expect($this->ended->all())->toBe(['revoked']);
});

it('sends a listed page behind auth to log in once it asks again as a guest', function () {
    endSessionFor('revoked');

    $this->get('/account')->assertRedirect('/account');
    $this->get('/account')->assertRedirect('/login');

    expect($this->ended->all())->toBe(['revoked']);
});

it('sends a head request to a listed page to log in as before', function () {
    endSessionFor('revoked');

    $this->call('HEAD', '/welcome')->assertRedirect('/login');
});

it('sends a route without a name to log in as before', function () {
    endSessionFor('revoked');

    $this->get('/unnamed')->assertRedirect('/login');
    expect(session('url.intended'))->toEndWith('/unnamed');
});

it('still answers json requests to a listed page with a 401', function () {
    endSessionFor('revoked');

    $this->getJson('/welcome')->assertUnauthorized()->assertJsonPath('status', 'signed-out');
    expect($this->ended->all())->toBe(['revoked']);
});

// A redirect would be followed with the same headers, so a partial reload
// would come back with only the props it asked for, still showing who was
// signed in. A full page load starts the page over as a guest.
it('has inertia load a listed page in full for :dataset', function (array $headers) {
    endSessionFor('revoked');

    $this->withHeaders([...inertiaVisit(), ...$headers])->get('/welcome?b=2&a=1')
        ->assertConflict()
        ->assertHeader('X-Inertia-Location', 'http://localhost/welcome?a=1&b=2')
        ->assertHeaderMissing('Location')
        ->assertHeader('Clear-Site-Data', '"cache", "storage"')
        ->assertSessionMissing('status');

    $this->assertGuest();
    expect(session()->has('url.intended'))->toBeFalse()
        ->and($this->ended->all())->toBe(['revoked']);

    $this->flushHeaders()->get('/welcome?a=1&b=2')->assertOk()->assertSee('guest');
    expect($this->ended->all())->toBe(['revoked']);
})->with([
    'a visit' => [[]],
    'a partial reload' => [['X-Inertia-Partial-Component' => 'Welcome', 'X-Inertia-Partial-Data' => 'notifications']],
    'a prefetch' => [['Purpose' => 'prefetch']],
]);

it('carries on as a guest when a remembered browser comes back and :dataset', function (string $case, string $reason) {
    $cookies = guestCookies(test()->withHeader('User-Agent', FIREFOX)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]));

    match ($case) {
        'gone' => DB::table('keyring_sessions')->delete(),
        'idle' => $this->travel(15)->days(),
        'lapsed' => config(['keyring.sessions.end_on_lapse' => true]),
    };

    $this->flushSession();
    $response = rememberedBrowser($cookies)->get('/welcome?b=2&a=1')
        ->assertRedirect('/welcome?a=1&b=2')
        ->assertHeader('Clear-Site-Data', '"cache", "storage"')
        ->assertCookieExpired(Auth::guard()->getRecallerName())
        ->assertCookieExpired('remembered_session');

    expect($this->ended->all())->toBe([$reason]);

    $this->flushSession();
    rememberedBrowser(cookiesAfter($response, $cookies))->get($response->headers->get('Location'))->assertOk()->assertSee('guest');

    $this->assertGuest();
    expect($this->ended->all())->toBe([$reason]);
})->with([
    'its record is gone' => ['gone', 'expired'],
    'it stayed away too long' => ['idle', 'idle'],
    'sessions end with their level' => ['lapsed', 'expired'],
]);

it('carries on as a guest on the cookie session driver', function () {
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');

    $cookies = cookiesAfter($this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']));
    app(SessionRegistry::class)->revoke(session(Sessions::KEY));

    $this->flushSession();
    $response = rememberedBrowser($cookies)->get('/welcome')->assertRedirect('/welcome');
    expect($this->ended->all())->toBe(['revoked']);

    $this->flushSession();
    rememberedBrowser(cookiesAfter($response, $cookies))->get('/welcome')->assertOk()->assertSee('guest');

    $this->assertGuest();
    expect($this->ended->all())->toBe(['revoked']);
});

it('sends a post to a listed route to log in as before', function () {
    endSessionFor('revoked');

    $this->post('/welcome')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');
});

it('sends every page to log in when the config is :dataset', function (mixed $routes) {
    config(['keyring.sessions' => $routes === 'missing'
        ? Arr::except(config('keyring.sessions'), 'continue_as_guest')
        : [...config('keyring.sessions'), 'continue_as_guest' => $routes]]);

    endSessionFor('revoked');

    $this->get('/welcome')->assertRedirect('/login');
    expect($this->ended->all())->toBe(['revoked']);
})->with([
    'null' => [null],
    'missing' => ['missing'],
    'empty' => [[]],
    'a string' => ['welcome'],
    'a list with something other than names' => [['welcome', 3]],
    'a list with an empty name' => [['welcome', '']],
    'keyed by name' => [['page' => 'welcome']],
]);

it('goes around the app\'s own signed-out response on listed pages only', function () {
    Keyring::respondWith(SignedOutResponse::class, fn ($app, array $with) => new class($with['reason']) implements SignedOutResponse
    {
        public function __construct(public string $reason) {}

        public function toResponse($request)
        {
            return response("signed out: {$this->reason}", 419);
        }
    });

    endSessionFor('revoked');
    $this->get('/welcome')->assertRedirect('/welcome');

    endSessionFor('revoked');
    $this->get('/pricing')->assertStatus(419)->assertSee('signed out: revoked');
});
