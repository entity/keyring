<?php

declare(strict_types=1);

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Events\SessionEnded;
use Keyring\Facades\Keyring;
use Keyring\Risk\Action;
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

    config(['keyring.sessions.continue_as_guest' => ['welcome', 'welcome.store', 'docs.*', 'unnamed']]);

    $this->freezeSecond();
    $this->user = taylor();
    $this->ended = collect();

    Event::listen(fn (SessionEnded $event) => $this->ended->push($event->reason));
});

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

    $sign();

    match ($reason) {
        'revoked' => app(SessionRegistry::class)->revoke(session(Sessions::KEY)),
        'expired' => test()->travel(62)->minutes(),
        'idle' => test()->travel(3)->hours(),
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

dataset('reasons', ['revoked', 'expired', 'idle', 'not_allowed', 'risk', 'reused']);

it('asks for a listed page again as a guest when the session ended as :dataset', function (string $reason) {
    $cookies = endSessionFor($reason);

    $response = visitAfterEnding($reason, $cookies, '/welcome?b=2&a=1')
        ->assertRedirect('/welcome?a=1&b=2')
        ->assertHeader('Clear-Site-Data', '"cache", "storage"')
        ->assertSessionMissing('status');

    $this->assertGuest();
    expect(session()->has('url.intended'))->toBeFalse()
        ->and($this->ended->all())->toBe([$reason]);

    // The browser is left with no session to carry on and no cookie to
    // bring one back, so following the redirect lands as a guest, once.
    if ($cookies !== []) {
        $response->assertCookieExpired(Auth::guard()->getRecallerName())->assertCookieExpired('remembered_session');
        $cookies = guestCookies($response);
    }

    visitAfterEnding($reason, $cookies, $response->headers->get('Location'))->assertOk()->assertSee('guest');

    $this->assertGuest();
    expect($this->ended->all())->toBe([$reason]);
})->with('reasons');

it('sends an unlisted page to log in as before when the session ended as :dataset', function (string $reason) {
    $cookies = endSessionFor($reason);

    visitAfterEnding($reason, $cookies, '/pricing')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

    expect(session('url.intended'))->toEndWith('/pricing')
        ->and($this->ended->all())->toBe([$reason]);
})->with('reasons');

it('matches route names with wildcards', function () {
    endSessionFor('revoked');

    $this->get('/docs/install')->assertRedirect('/docs/install');
    $this->get('/docs/install')->assertOk()->assertSee('guest');
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

it('treats an inertia visit to a listed page as a page visit', function () {
    endSessionFor('revoked');

    $this->inertia()->getJson('/welcome')->assertRedirect('/welcome')->assertHeader('Clear-Site-Data');
    expect(session()->has('url.intended'))->toBeFalse();
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
