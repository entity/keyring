<?php

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
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

    foreach (['__Host-keyring_device', '__Host-keyring_remember'] as $name) {
        $cookie = $response->getCookie($name);

        expect($cookie)->not->toBeNull()
            ->and($cookie->isSecure())->toBeTrue()
            ->and($cookie->isHttpOnly())->toBeTrue()
            ->and($cookie->getSameSite())->toBe('lax')
            ->and($cookie->getPath())->toBe('/')
            ->and($cookie->getDomain())->toBeNull();
    }

    $response->assertCookieMissing('keyring_device')->assertCookieMissing('keyring_remember');
});

it('does the same when the session cookie is kept to HTTPS, whatever APP_URL says', function () {
    config(['session.secure' => true]);

    $response = signInHolding(remember: true);

    expect($response->getCookie('__Host-keyring_device')->isSecure())->toBeTrue()
        ->and($response->getCookie('__Host-keyring_remember')->isSecure())->toBeTrue();
});

it('falls back to the __Secure- prefix for cookies shared with subdomains or kept to a path', function (array $session, ?string $domain, string $path) {
    servedOverHttps();
    config($session);

    $response = signInHolding(remember: true);

    foreach (['__Secure-keyring_device', '__Secure-keyring_remember'] as $name) {
        $cookie = $response->getCookie($name);

        expect($cookie)->not->toBeNull()
            ->and($cookie->isSecure())->toBeTrue()
            ->and($cookie->getDomain())->toBe($domain)
            ->and($cookie->getPath())->toBe($path);
    }

    $response->assertCookieMissing('__Host-keyring_device')->assertCookieMissing('__Host-keyring_remember');
})->with([
    'a cookie domain' => [['session.domain' => '.example.com'], '.example.com', '/'],
    'a cookie path' => [['session.path' => '/app'], null, '/app'],
]);

it('leaves the names alone over plain HTTP, where a browser would refuse a prefix', function () {
    $response = signInHolding(remember: true);

    foreach (['keyring_device', 'keyring_remember'] as $name) {
        expect($response->getCookie($name)->isSecure())->toBeFalse()
            ->and($response->getCookie($name)->isHttpOnly())->toBeTrue();
    }

    // Like the session cookie, they're still kept to HTTPS when that's how
    // the request came.
    $secure = browserHolding()->post('https://localhost/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    expect($secure->getCookie('keyring_device')->isSecure())->toBeTrue();
});

it('uses a name the app set exactly as it is, and still keeps it to HTTPS', function () {
    servedOverHttps();
    config(['keyring.devices.cookie' => 'acme_device', 'keyring.sessions.remember_cookie' => 'acme_remember']);

    $response = signInHolding(remember: true);

    expect($response->getCookie('acme_device')->isSecure())->toBeTrue()
        ->and($response->getCookie('acme_remember')->isSecure())->toBeTrue();

    $response->assertCookieMissing('__Host-acme_device')->assertCookieMissing('__Host-keyring_device');

    // And the device is known by it.
    Event::fake([NewDeviceSignedIn::class]);
    signInHolding(['acme_device' => $response->getCookie('acme_device')->getValue()]);

    Event::assertNotDispatched(NewDeviceSignedIn::class);
    expect(Device::count())->toBe(1);
});

describe('a browser holding the cookies from before the app was served over HTTPS', function () {
    beforeEach(function () {
        $response = signInHolding(remember: true);

        $this->device = $response->getCookie('keyring_device')->getValue();
        $this->remembered = $response->getCookie('keyring_remember')->getValue();
        $this->recaller = [Auth::guard()->getRecallerName() => $response->getCookie(Auth::guard()->getRecallerName())->getValue()];

        servedOverHttps();
    });

    it('is still the same device, and gets its cookie under the new name', function () {
        Event::fake([NewDeviceSignedIn::class]);

        $response = signInHolding(['keyring_device' => $this->device]);

        Event::assertNotDispatched(NewDeviceSignedIn::class);

        expect(Device::count())->toBe(1)
            ->and($response->getCookie('__Host-keyring_device')->getValue())->toBe($this->device)
            ->and($response->getCookie('__Host-keyring_device')->isSecure())->toBeTrue();

        $response->assertCookieExpired('keyring_device');

        // From then on the new name is the one that counts.
        signInHolding(['__Host-keyring_device' => $this->device])->assertCookieMissing('keyring_device');

        Event::assertNotDispatched(NewDeviceSignedIn::class);
        expect(Device::count())->toBe(1);
    });

    it('is still remembered, and gets that cookie under the new name too', function () {
        $this->travel(3)->hours();

        $response = browserHolding([...$this->recaller, 'keyring_remember' => $this->remembered, 'keyring_device' => $this->device])
            ->get('/home')
            ->assertOk();

        $cookie = $response->getCookie('__Host-keyring_remember');

        expect(session(Sessions::KEY))->toBe($this->remembered)
            ->and($cookie->getValue())->toBe($this->remembered)
            ->and($cookie->isSecure())->toBeTrue()
            ->and($cookie->getExpiresTime())->toBe(app(SessionRegistry::class)->find($this->remembered)->expiresAt)
            ->and($response->getCookie('__Host-keyring_device')->getValue())->toBe($this->device)
            ->and(Device::count())->toBe(1);

        $response->assertCookieExpired('keyring_remember')->assertCookieExpired('keyring_device');

        $this->travel(3)->hours();

        browserHolding([...$this->recaller, '__Host-keyring_remember' => $this->remembered, '__Host-keyring_device' => $this->device])
            ->get('/home')
            ->assertOk()
            ->assertCookieMissing('__Host-keyring_remember');
    });

    it('has both names taken back when it signs out', function () {
        browserHolding([...$this->recaller, 'keyring_remember' => $this->remembered])->get('/home')->assertOk();

        $this->withCookies(['__Host-keyring_remember' => $this->remembered])
            ->post('/logout')
            ->assertCookieExpired('keyring_remember')
            ->assertCookieExpired('__Host-keyring_remember');
    });

    it('is not known by the old cookie once it holds the new one', function () {
        Event::fake([NewDeviceSignedIn::class]);

        $response = signInHolding(['keyring_device' => $this->device, '__Host-keyring_device' => str_repeat('a', 40)]);

        Event::assertDispatched(NewDeviceSignedIn::class);
        expect($response->getCookie('__Host-keyring_device')->getValue())->not->toBe($this->device);
    });

    it('never gives a new device the token of the old cookie', function () {
        // Anything on the domain could set a cookie without the prefix, so
        // one holding another account's token is planted, not shared.
        User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $response = signInHolding(['keyring_device' => $this->device], email: 'abigail@example.com');

        expect($response->getCookie('__Host-keyring_device')->getValue())->not->toBe($this->device)
            ->and(Device::query()->withToken($this->device)->count())->toBe(1);

        $response->assertCookieExpired('keyring_device');
    });

    it('is refused a remembered session the old cookie names for someone else', function () {
        $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $theirs = signInHolding(remember: true, email: 'abigail@example.com')->getCookie('__Host-keyring_remember')->getValue();

        expect(app(SessionRegistry::class)->find($theirs)->userId)->toBe((string) $abigail->id);

        browserHolding([...$this->recaller, 'keyring_remember' => $theirs])->get('/home')->assertRedirect('/login');
        $this->assertGuest();
    });
});

it('takes a prefixed cookie back with a response that is kept to HTTPS as well', function () {
    servedOverHttps();
    $response = signInHolding(remember: true);

    $forgotten = $this->withCookies(['__Host-keyring_remember' => $response->getCookie('__Host-keyring_remember')->getValue()])
        ->post('/logout')
        ->assertCookieExpired('__Host-keyring_remember')
        ->getCookie('__Host-keyring_remember');

    // A browser ignores a "__Host-" cookie that isn't Secure, expired or not.
    expect($forgotten->isSecure())->toBeTrue()
        ->and($forgotten->getPath())->toBe('/')
        ->and($forgotten->getDomain())->toBeNull();
});
