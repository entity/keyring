<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Devices\DeviceManager;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Models\Device;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\TestCase;

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    $this->user = taylor();
});

/**
 * A request from a browser holding these cookies and no others: the test
 * client would otherwise send every cookie an earlier response set, and each
 * response would carry what was queued for the ones before it.
 *
 * @param  array<string, string>  $cookies
 */
function browserHolding(array $cookies = []): TestCase
{
    Cookie::flushQueuedCookies();
    Auth::forgetGuards();

    return test()->flushSession()->withHeader('User-Agent', FIREFOX)->withCredentials()->withOnlyCookies($cookies);
}

/**
 * @param  array<string, string>  $cookies
 */
function signInHolding(array $cookies = [], bool $remember = false, string $email = 'taylor@example.com'): TestResponse
{
    return browserHolding($cookies)->post('/login', ['email' => $email, 'password' => 'password', 'remember' => $remember])->assertRedirect('/dashboard');
}

function servedOverHttps(): void
{
    config(['app.url' => 'https://app.example.com']);
}

it('names both cookies with the __Host- prefix and keeps them to HTTPS when APP_URL is https', function () {
    servedOverHttps();

    $response = signInHolding(remember: true);

    foreach (['__Host-known_device', '__Host-remembered_session'] as $name) {
        $cookie = $response->getCookie($name);

        expect($cookie)->not->toBeNull()
            ->and($cookie->isSecure())->toBeTrue()
            ->and($cookie->isHttpOnly())->toBeTrue()
            ->and($cookie->getSameSite())->toBe('lax')
            ->and($cookie->getPath())->toBe('/')
            ->and($cookie->getDomain())->toBeNull();
    }

    $response->assertCookieMissing('known_device')->assertCookieMissing('remembered_session');
});

it('does the same when the session cookie is kept to HTTPS, whatever APP_URL says', function () {
    config(['session.secure' => true]);

    $response = signInHolding(remember: true);

    expect($response->getCookie('__Host-known_device')->isSecure())->toBeTrue()
        ->and($response->getCookie('__Host-remembered_session')->isSecure())->toBeTrue();
});

it('falls back to the __Secure- prefix for cookies shared with subdomains or kept to a path', function (array $session, ?string $domain, string $path) {
    servedOverHttps();
    config($session);

    $response = signInHolding(remember: true);

    foreach (['__Secure-known_device', '__Secure-remembered_session'] as $name) {
        $cookie = $response->getCookie($name);

        expect($cookie)->not->toBeNull()
            ->and($cookie->isSecure())->toBeTrue()
            ->and($cookie->getDomain())->toBe($domain)
            ->and($cookie->getPath())->toBe($path);
    }

    $response->assertCookieMissing('__Host-known_device')->assertCookieMissing('__Host-remembered_session');
})->with([
    'a cookie domain' => [['session.domain' => '.example.com'], '.example.com', '/'],
    'a cookie path' => [['session.path' => '/app'], null, '/app'],
]);

it('leaves the names alone over plain HTTP, where a browser would refuse a prefix', function () {
    $response = signInHolding(remember: true);

    foreach (['known_device', 'remembered_session'] as $name) {
        expect($response->getCookie($name)->isSecure())->toBeFalse()
            ->and($response->getCookie($name)->isHttpOnly())->toBeTrue();
    }

    // Like the session cookie, they're still kept to HTTPS when that's how
    // the request came.
    $secure = browserHolding()->post('https://localhost/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    expect($secure->getCookie('known_device')->isSecure())->toBeTrue();
});

it('names its cookies for what they are for, and not for what set them', function (string $served, string $prefix) {
    config(match ($served) {
        'http' => [],
        'https' => ['app.url' => 'https://app.example.com'],
        'subdomains' => ['app.url' => 'https://app.example.com', 'session.domain' => '.example.com'],
    });

    $response = signInHolding(remember: true);
    $names = array_map(fn ($cookie) => $cookie->getName(), $response->headers->getCookies());

    // A name that gives the package away tells an attacker what to look up.
    expect($names)->toContain($prefix.'known_device', $prefix.'remembered_session')
        ->and(array_values(array_filter($names, fn (string $name) => str_contains(strtolower($name), 'keyring'))))->toBe([])
        ->and(app(DeviceManager::class)->cookie())->toBe($prefix.'known_device')
        ->and(app(Sessions::class)->rememberCookie())->toBe($prefix.'remembered_session');
})->with([
    'over plain http' => ['http', ''],
    'over https' => ['https', '__Host-'],
    'shared with subdomains' => ['subdomains', '__Secure-'],
]);

it('uses a name the app set exactly as it is, and still keeps it to HTTPS', function () {
    servedOverHttps();
    config(['keyring.devices.cookie' => 'acme_device', 'keyring.sessions.remember_cookie' => 'acme_remember']);

    $response = signInHolding(remember: true);

    expect($response->getCookie('acme_device')->isSecure())->toBeTrue()
        ->and($response->getCookie('acme_remember')->isSecure())->toBeTrue();

    $response->assertCookieMissing('__Host-acme_device')->assertCookieMissing('__Host-known_device');

    // And the device is known by it.
    Event::fake([NewDeviceSignedIn::class]);
    signInHolding(['acme_device' => $response->getCookie('acme_device')->getValue()]);

    Event::assertNotDispatched(NewDeviceSignedIn::class);
    expect(Device::count())->toBe(1);
});

describe('a browser holding the cookies from before the app was served over HTTPS', function () {
    beforeEach(function () {
        $response = signInHolding(remember: true);

        $this->device = $response->getCookie('known_device')->getValue();
        $this->remembered = $response->getCookie('remembered_session')->getValue();
        $this->recaller = [Auth::guard()->getRecallerName() => $response->getCookie(Auth::guard()->getRecallerName())->getValue()];

        servedOverHttps();
    });

    it('is still the same device, and gets its cookie under the new name', function () {
        Event::fake([NewDeviceSignedIn::class]);

        $response = signInHolding(['known_device' => $this->device]);

        Event::assertNotDispatched(NewDeviceSignedIn::class);

        expect(Device::count())->toBe(1)
            ->and($response->getCookie('__Host-known_device')->getValue())->toBe($this->device)
            ->and($response->getCookie('__Host-known_device')->isSecure())->toBeTrue();

        $response->assertCookieExpired('known_device');

        // From then on the new name is the one that counts.
        signInHolding(['__Host-known_device' => $this->device])->assertCookieMissing('known_device');

        Event::assertNotDispatched(NewDeviceSignedIn::class);
        expect(Device::count())->toBe(1);
    });

    it('is still remembered, and gets that cookie under the new name too', function () {
        $this->travel(3)->hours();

        $response = browserHolding([...$this->recaller, 'remembered_session' => $this->remembered, 'known_device' => $this->device])
            ->get('/home')
            ->assertOk();

        // Coming back replaces the record and its cookie, which goes out
        // under the new name.
        $cookie = $response->getCookie('__Host-remembered_session');
        $carried = session(Sessions::KEY);

        expect($carried)->not->toBe($this->remembered)
            ->and(app(SessionRegistry::class)->find($this->remembered)->replacedBy)->toBe($carried)
            ->and($cookie->getValue())->toBe($carried)
            ->and($cookie->isSecure())->toBeTrue()
            ->and($cookie->getExpiresTime())->toBe(app(SessionRegistry::class)->find($carried)->expiresAt)
            ->and($response->getCookie('__Host-known_device')->getValue())->toBe($this->device)
            ->and(Device::count())->toBe(1);

        $response->assertCookieExpired('remembered_session')->assertCookieExpired('known_device');

        // From then on the new names are the ones that count.
        $this->travel(3)->hours();

        browserHolding([...$this->recaller, '__Host-remembered_session' => $carried, '__Host-known_device' => $this->device])
            ->get('/home')
            ->assertOk()
            ->assertCookieMissing('remembered_session')
            ->assertCookieMissing('known_device');

        expect(Device::count())->toBe(1);
    });

    it('has both names taken back when it signs out', function () {
        browserHolding([...$this->recaller, 'remembered_session' => $this->remembered])->get('/home')->assertOk();

        $this->withCookies(['__Host-remembered_session' => $this->remembered])
            ->post('/logout')
            ->assertCookieExpired('remembered_session')
            ->assertCookieExpired('__Host-remembered_session');
    });

    it('is not known by the old cookie once it holds the new one', function () {
        Event::fake([NewDeviceSignedIn::class]);

        $response = signInHolding(['known_device' => $this->device, '__Host-known_device' => str_repeat('a', 40)]);

        Event::assertDispatched(NewDeviceSignedIn::class);
        expect($response->getCookie('__Host-known_device')->getValue())->not->toBe($this->device);
    });

    it('never gives a new device the token of the old cookie', function () {
        // Anything on the domain could set a cookie without the prefix, so
        // one holding another account's token is planted, not shared.
        User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $response = signInHolding(['known_device' => $this->device], email: 'abigail@example.com');

        expect($response->getCookie('__Host-known_device')->getValue())->not->toBe($this->device)
            ->and(Device::query()->withToken($this->device)->count())->toBe(1);

        $response->assertCookieExpired('known_device');
    });

    it('is refused a remembered session the old cookie names for someone else', function () {
        $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $theirs = signInHolding(remember: true, email: 'abigail@example.com')->getCookie('__Host-remembered_session')->getValue();

        expect(app(SessionRegistry::class)->find($theirs)->userId)->toBe((string) $abigail->id);

        browserHolding([...$this->recaller, 'remembered_session' => $theirs])->get('/home')->assertRedirect('/login');
        $this->assertGuest();
    });
});

it('takes a prefixed cookie back with a response that is kept to HTTPS as well', function () {
    servedOverHttps();
    $response = signInHolding(remember: true);

    $forgotten = $this->withCookies(['__Host-remembered_session' => $response->getCookie('__Host-remembered_session')->getValue()])
        ->post('/logout')
        ->assertCookieExpired('__Host-remembered_session')
        ->getCookie('__Host-remembered_session');

    // A browser ignores a "__Host-" cookie that isn't Secure, expired or not.
    expect($forgotten->isSecure())->toBeTrue()
        ->and($forgotten->getPath())->toBe('/')
        ->and($forgotten->getDomain())->toBeNull();
});
