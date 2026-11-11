<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\Signal;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Assurance;
use Keyring\Events\DeviceRevoked;
use Keyring\Events\LoggedOut;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Events\SessionsRevoked;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Features;
use Keyring\Http\Middleware\AddSecurityHeaders;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    $this->user = taylor();
});

function login(array $cookies = []): TestResponse
{
    return test()->withHeader('User-Agent', FIREFOX)
        ->withCookies($cookies)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
}

function deviceCookie(TestResponse $response): string
{
    return $response->getCookie('known_device')->getValue();
}

dataset('registries', ['database', 'cache']);

it('remembers devices and announces new ones', function () {
    Event::fake([NewDeviceSignedIn::class]);

    $response = login()->assertCookie('known_device');
    $token = deviceCookie($response);

    $device = Device::sole();
    expect($device->name)->toBe('Firefox on Windows')
        ->and($device->token_hash)->toBe(hash('sha256', $token));

    Event::assertDispatchedTimes(NewDeviceSignedIn::class, 1);

    $this->post('/logout');
    login(['known_device' => $token]);

    Event::assertDispatchedTimes(NewDeviceSignedIn::class, 1);
    expect(Device::count())->toBe(1);
});

describe('an account that keeps signing in from new browsers', function () {
    /**
     * Sign in from a browser the account hasn't used, a minute after the
     * last, and return its device cookie. It stays signed in.
     */
    function newBrowser(): string
    {
        test()->travel(1)->minutes();
        test()->flushSession();
        Auth::forgetGuards();

        return deviceCookie(login(['known_device' => 'not a device the account has'])->assertRedirect('/dashboard'));
    }

    it('keeps as many devices as the limit, forgetting whichever was seen longest ago', function () {
        config(['keyring.devices.limit' => 3]);

        $first = newBrowser();
        $kept = [newBrowser(), newBrowser(), newBrowser()];

        expect(Device::query()->oldest('last_seen_at')->pluck('token_hash')->all())
            ->toBe(array_map(fn (string $token) => hash('sha256', $token), $kept));

        // The forgotten browser is new to the account again.
        Event::fake([NewDeviceSignedIn::class]);
        $this->post('/logout');
        login(['known_device' => $first]);

        Event::assertDispatchedTimes(NewDeviceSignedIn::class, 1);
        expect(Device::count())->toBe(3);
    });

    it('signs the forgotten device out', function (string $driver) {
        config(['keyring.devices.limit' => 2, 'keyring.sessions.driver' => $driver]);

        newBrowser();
        $record = session(Sessions::KEY);

        newBrowser();
        newBrowser();

        expect(app(SessionRegistry::class)->find($record)?->revokedAt)->not->toBeNull()
            ->and(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(2);
    })->with('registries');

    it('goes by when a device was last seen, not when it was first', function () {
        config(['keyring.devices.limit' => 2]);

        $first = newBrowser();
        $second = newBrowser();

        // The first one comes back, so the second is now the stalest.
        $this->travel(1)->minutes();
        $this->flushSession();
        Auth::forgetGuards();
        login(['known_device' => $first])->assertRedirect('/dashboard');

        newBrowser();

        expect(Device::query()->where('token_hash', hash('sha256', $first))->exists())->toBeTrue()
            ->and(Device::query()->where('token_hash', hash('sha256', $second))->exists())->toBeFalse();
    });

    it('does not count devices that were signed out, or another account\'s', function () {
        config(['keyring.devices.limit' => 2]);
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        foreach (range(1, 3) as $n) {
            Device::make(['token_hash' => Device::hashToken("another account's {$n}"), 'first_seen_at' => now(), 'last_seen_at' => now()])
                ->authenticatable()->associate($other)->save();
        }

        newBrowser();
        app(DeviceManager::class)->revoke(Device::query()->ownedBy($this->user)->sole());

        newBrowser();
        newBrowser();

        expect(Device::query()->ownedBy($this->user)->active()->count())->toBe(2)
            ->and(Device::query()->ownedBy($this->user)->count())->toBe(3)
            ->and(Device::query()->ownedBy($other)->count())->toBe(3);
    });

    it('keeps every device when there is no limit', function () {
        config(['keyring.devices.limit' => null]);

        foreach (range(1, 6) as $browser) {
            newBrowser();
        }

        expect(Device::count())->toBe(6);
    });
});

describe('an account signed in more times than it may be', function () {
    /**
     * Sign in from another browser, a minute after the last, and return its
     * session's registry ID. It stays signed in.
     */
    function anotherSession(bool $remember = false): string
    {
        test()->travel(1)->minutes();
        test()->flushSession();
        Auth::forgetGuards();

        test()->withHeader('User-Agent', FIREFOX)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => $remember])
            ->assertRedirect('/dashboard');

        return session(Sessions::KEY);
    }

    function activeSessions(): array
    {
        return app(SessionRegistry::class)->forUser(test()->user)->map->id->all();
    }

    it('may be signed in a hundred times at once, unless the app says otherwise', function () {
        expect(config('keyring.sessions.max'))->toBe(100);
    });

    it('ends whichever session has gone unused longest', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => 3]);
        $registry = app(SessionRegistry::class);

        [$first, $second, $third] = [anotherSession(), anotherSession(), anotherSession()];

        // The first one is used again, so the second is now the stalest.
        $this->travel(1)->minutes();
        $registry->update($first, ['lastActivityAt' => now()->getTimestamp()]);

        $fourth = anotherSession();

        expect($registry->find($second)->revokedAt)->not->toBeNull()
            ->and(activeSessions())->toEqualCanonicalizing([$first, $third, $fourth]);
    })->with('registries');

    it('signs the session it ended out on its next request', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => 1]);

        anotherSession();
        $session = session()->all();
        $latest = anotherSession();

        session()->flush();
        session()->replace($session);
        Auth::forgetGuards();
        $this->get('/home')->assertRedirect('/login');

        expect(SecurityEvent::query()->where('type', 'session_ended')->sole()->meta)->toBe(['reason' => 'revoked'])
            ->and(activeSessions())->toBe([$latest]);
    })->with('registries');

    it('ends one that has idled out before one that can still be carried on', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => 2]);
        $registry = app(SessionRegistry::class);

        // A remembered browser, then one closed without signing out and not
        // used for three hours: used more recently, but over.
        $remembered = anotherSession(remember: true);
        $closed = anotherSession();
        $this->travel(3)->hours();

        $latest = anotherSession();

        expect($registry->find($closed)->revokedAt)->not->toBeNull()
            ->and(activeSessions())->toEqualCanonicalizing([$remembered, $latest]);
    })->with('registries');

    it('does not count a session that was signed out, or a record its session moved on from', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => 2]);
        $registry = app(SessionRegistry::class);

        $signedOut = anotherSession();
        $this->post('/logout');

        $moved = anotherSession();
        $registry->replace($moved, $successor = $registry->find($moved)->with(['id' => str_repeat('s', 40)]));

        $latest = anotherSession();

        expect($registry->find($signedOut)->revokedAt)->not->toBeNull()
            ->and($registry->find($successor->id)->revokedAt)->toBeNull()
            ->and(activeSessions())->toEqualCanonicalizing([$successor->id, $latest]);
    })->with('registries');

    it('counts a session the app signed in itself', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => 1]);
        Route::middleware('web')->post('/oauth/callback', fn () => tap('welcome', fn () => Auth::login($this->user)));

        $first = anotherSession();

        $this->travel(1)->minutes();
        $this->flushSession();
        Auth::forgetGuards();
        $this->post('/oauth/callback')->assertOk();

        expect(app(SessionRegistry::class)->find($first)->revokedAt)->not->toBeNull()
            ->and(activeSessions())->toBe([session(Sessions::KEY)]);
    })->with('registries');

    it('leaves another account\'s sessions out of it', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => 1]);
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
        $theirs = session(Sessions::KEY);

        anotherSession();
        anotherSession();

        expect(app(SessionRegistry::class)->find($theirs)->revokedAt)->toBeNull()
            ->and(app(SessionRegistry::class)->forUser($other))->toHaveCount(1);
    })->with('registries');

    it('ends none when there is no limit', function (string $driver) {
        config(['keyring.sessions.driver' => $driver, 'keyring.sessions.max' => null]);

        foreach (range(1, 5) as $browser) {
            anotherSession();
        }

        expect(activeSessions())->toHaveCount(5);
    })->with('registries');

    it('ends every one past a limit that was lowered', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        [$first, $second, $third] = [anotherSession(), anotherSession(), anotherSession()];

        config(['keyring.sessions.max' => 2]);
        $fourth = anotherSession();

        expect(activeSessions())->toEqualCanonicalizing([$third, $fourth]);
    })->with('registries');
});

it('gives new device events a working "this wasn\'t me" link', function () {
    Event::fake([NewDeviceSignedIn::class, DeviceRevoked::class]);
    login();

    $url = null;
    Event::assertDispatched(NewDeviceSignedIn::class, function (NewDeviceSignedIn $event) use (&$url) {
        $url = $event->revokeUrl();

        return true;
    });

    $this->get('/home')->assertOk();

    // Opening the link only shows a page, so mail scanners can't sign anyone out.
    // Its URL is the signed link, so the page sends no Referer to anyone.
    $this->inertia()->get($url)->assertOk()->assertJsonPath('component', 'auth/device-report')->assertHeader('Referrer-Policy', 'no-referrer')->assertHeader('X-Frame-Options', 'DENY');
    $this->flushHeaders();
    expect(Device::sole()->isRevoked())->toBeFalse();

    postSignedLink($url)->assertRedirect('/login');

    $this->get('/home')->assertRedirect('/login');
    expect(Device::sole()->isRevoked())->toBeTrue();
    Event::assertDispatched(DeviceRevoked::class, fn ($event) => $event->reported);
});

it('lets the policy skip the second factor on a trusted device', function () {
    Keyring::require(fn (User $user, Attempt $attempt) => $attempt->device()?->isTrusted()
        ? Requirement::aal1()
        : Requirement::aal2()->ifEnrolled());

    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    login()->assertRedirect(route('keyring.login.challenge'));
    $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.canTrustDevice', true);

    $response = $this->post(route('keyring.login.verify', 'totp'), [
        'code' => totpCode($totp->secret),
        'trust' => true,
    ])->assertRedirect('/dashboard');

    expect(Device::sole()->isTrusted())->toBeTrue();

    $token = deviceCookie($response);
    $this->post('/logout');

    login(['known_device' => $token])->assertRedirect('/dashboard');
});

it('signs a revoked session out on its next request', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    login();
    $this->get('/home')->assertOk();

    $id = session(Sessions::KEY);
    app(SessionRegistry::class)->revoke($id);

    $this->get('/home')->assertRedirect('/login');
    $this->assertGuest();
})->with('registries');

it('signs out everywhere else', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    $registry = app(SessionRegistry::class);

    login();
    $current = session(Sessions::KEY);

    $other = new RegisteredSession(
        id: 'other',
        userId: (string) $this->user->id,
        guard: 'web',
        deviceId: null,
        assurance: Assurance::AAL1,
        ip: null,
        userAgent: null,
        authenticatedAt: now()->getTimestamp(),
        lastActivityAt: now()->getTimestamp(),
        expiresAt: now()->addHour()->getTimestamp(),
    );
    $registry->save($other);
    expect($registry->forUser($this->user))->toHaveCount(2);

    $this->deleteJson(route('keyring.devices.destroy-others'))->assertOk();

    expect($registry->find($other->id)->revokedAt)->not->toBeNull()
        ->and($registry->find($current)->revokedAt)->toBeNull();

    $this->get('/home')->assertOk();
})->with('registries');

it('stops trusting the other devices when signing out everywhere else', function () {
    login();
    $here = Device::sole();
    $here->forceFill(['trusted_until' => now()->addDay()])->save();
    $elsewhere = $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'elsewhere'), 'trusted_until' => now()->addDay()]);

    $this->deleteJson(route('keyring.devices.destroy-others'))->assertOk();

    expect($here->fresh()->isTrusted())->toBeTrue()
        ->and($elsewhere->fresh()->isTrusted())->toBeFalse();

    app(Sessions::class)->signOutEverywhere($this->user);

    expect($here->fresh()->isTrusted())->toBeFalse();
});

it('lists devices with the current one marked', function () {
    login();

    $this->getJson(route('keyring.devices.index'))
        ->assertOk()
        ->assertJsonPath('devices.0.name', 'Firefox on Windows')
        ->assertJsonPath('devices.0.sessions', 1);
});

it('enforces the absolute timeout', function () {
    config(['keyring.sessions.absolute' => '1h']);
    login();

    $this->travel(61)->minutes();

    $this->get('/home')->assertRedirect('/login');
});

it('leaves other remembered browsers signed in when a session times out', function () {
    config(['keyring.sessions.remember_idle' => '10m']);
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
    $token = $this->user->fresh()->remember_token;

    $this->travel(11)->minutes();
    $this->get('/home')->assertRedirect('/login');

    expect($this->user->fresh()->remember_token)->toBe($token);
});

it('keeps "remember me" no longer than a session lasts', function () {
    $response = test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);

    $cookie = collect($response->headers->getCookies())->first(fn ($cookie) => str_starts_with($cookie->getName(), 'remember_web_'));

    expect($cookie->getExpiresTime())->toBeLessThanOrEqual(now()->addDays(30)->getTimestamp() + 60)
        ->toBeGreaterThan(now()->addDays(29)->getTimestamp());
});

it('enforces the idle timeout', function () {
    config(['keyring.sessions.idle' => '10m']);
    login();

    $this->travel(5)->minutes();
    $this->get('/home')->assertOk();

    $this->travel(11)->minutes();
    $this->get('/home')->assertRedirect('/login')->assertHeader('Clear-Site-Data', '"cache", "storage"');

    expect(SecurityEvent::query()->where('type', 'session_ended')->sole()->meta)->toBe(['reason' => 'idle']);
});

it('ends a session left unused for two hours, without being told to', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    login();

    $this->travel(119)->minutes();
    $this->get('/home')->assertOk();

    $this->travel(121)->minutes();
    $this->get('/home')->assertRedirect('/login');

    expect(SecurityEvent::query()->where('type', 'session_ended')->sole()->meta)->toBe(['reason' => 'idle']);
})->with('registries');

it('leaves inactivity to laravel\'s session lifetime when there is no idle limit', function () {
    config(['keyring.sessions.idle' => null]);
    login();

    $this->travel(29)->days();
    $this->get('/home')->assertOk();
});

it('does not list a session that has idled out, or count it on its device', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);

    // A browser that was closed without signing out.
    $token = deviceCookie(login());
    $this->travel(3)->hours();
    $this->flushSession();
    Auth::forgetGuards();

    login(['known_device' => $token]);

    expect(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(2)
        ->and(app(Sessions::class)->active($this->user)->map->id->all())->toBe([session(Sessions::KEY)]);

    $this->getJson(route('keyring.devices.index'))->assertJsonPath('devices.0.sessions', 1);
})->with('registries');

it('registers a session the app signs in itself on the response that signs it in', function () {
    Route::middleware('web')->post('/oauth/callback', fn () => tap('welcome', fn () => Auth::login($this->user)));

    $this->post('/oauth/callback')->assertOk();

    $id = session(Sessions::KEY);
    expect($id)->not->toBeNull()
        ->and(app(SessionRegistry::class)->find($id)->userId)->toBe((string) $this->user->id);
});

it('registers sessions that started some other way', function () {
    $this->actingAs($this->user)->get('/home')->assertOk();

    expect(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
});

describe('coming back with a "remember me" cookie', function () {
    beforeEach(function () {
        $response = test()->withHeader('User-Agent', FIREFOX)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);

        $this->device = deviceCookie($response);
        $this->registered = session(Sessions::KEY);
        $user = $this->user->fresh();

        // "Remember me" is Laravel's cookie and the one naming its session.
        $remembered = [
            Auth::guard()->getRecallerName() => $user->id.'|'.$user->remember_token.'|'.$user->password,
            'remembered_session' => $this->registered,
        ];

        // The session is gone and only the cookies are left.
        $this->flushSession();
        Auth::forgetGuards();

        $this->comeBack = fn (array $cookies = []) => $this->withHeader('User-Agent', FIREFOX)
            ->withCookies([...$remembered, ...$cookies])
            ->get('/home');
    });

    it('carries the session on, on the device it was remembered on', function () {
        Event::fake([NewDeviceSignedIn::class]);

        ($this->comeBack)(['known_device' => $this->device])->assertOk();

        expect(Device::count())->toBe(1)
            ->and(app(SessionRegistry::class)->find($this->registered)->replacedBy)->toBe(session(Sessions::KEY))
            ->and(app(SessionRegistry::class)->find(session(Sessions::KEY))->deviceId)->toBe(Device::sole()->id);
        Event::assertNotDispatched(NewDeviceSignedIn::class);
    });

    it('announces a browser the account has not used as a new device', function () {
        Event::fake([NewDeviceSignedIn::class]);
        $first = Device::sole();

        ($this->comeBack)()->assertOk()->assertCookie('known_device');

        // The record left behind keeps the device its cookie was issued on.
        expect(Device::count())->toBe(2)
            ->and(app(SessionRegistry::class)->find($this->registered)->deviceId)->toBe($first->id)
            ->and(app(SessionRegistry::class)->find(session(Sessions::KEY))->deviceId)->toBe(Device::query()->whereKeyNot($first->id)->sole()->id);
        Event::assertDispatchedTimes(NewDeviceSignedIn::class, 1);
    });

    it('is refused while the account is risk locked', function () {
        app(RiskLocks::class)->lock($this->user, 3600);

        ($this->comeBack)(['known_device' => $this->device])->assertRedirect('/login');

        $this->assertGuest();
        expect(SecurityEvent::query()->where('type', 'session_ended')->sole()->meta)->toBe(['reason' => 'risk']);
    });

    it('leaves a session that is already signed in alone while the account is risk locked', function () {
        ($this->comeBack)(['known_device' => $this->device])->assertOk();
        app(RiskLocks::class)->lock($this->user, 3600);

        $this->withHeader('User-Agent', FIREFOX)->get('/home')->assertOk();
    });
});

it('revokes the registered session on logout and clears site data', function () {
    login();
    $id = session(Sessions::KEY);

    $this->post('/logout')->assertHeader('Clear-Site-Data', '"cache", "storage"');

    expect(app(SessionRegistry::class)->find($id)->revokedAt)->not->toBeNull();
});

it('never lets auth pages be cached', function () {
    $this->get('/login')->assertHeader('Cache-Control', 'no-store, private');
});

it('tells the browser not to guess the type of a page, a redirect or JSON', function () {
    $this->inertia()->get('/login')->assertOk()->assertHeader('X-Content-Type-Options', 'nosniff');
    $this->flushHeaders()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect()->assertHeader('X-Content-Type-Options', 'nosniff');
    $this->getJson('/user/devices')->assertOk()->assertHeader('X-Content-Type-Options', 'nosniff');
    $this->postJson('/logout')->assertNoContent()->assertHeader('X-Content-Type-Options', 'nosniff');
    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertUnprocessable()->assertHeader('X-Content-Type-Options', 'nosniff');
});

it('will not be shown in a frame, whether it answers with a page, a redirect or JSON', function () {
    Route::middleware(['web', 'auth', 'keyring.fresh:5m'])->get('/billing', fn () => 'billing');

    $this->inertia()->get('/login')->assertOk()->assertHeader('X-Frame-Options', 'DENY');
    $this->flushHeaders()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect()->assertHeader('X-Frame-Options', 'DENY');
    $this->getJson('/user/devices')->assertOk()->assertHeader('X-Frame-Options', 'DENY');

    // The confirm page, where a password or a code is typed again.
    $this->freshAt(now()->subHour())->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    $this->inertia()->get(route('keyring.confirm.challenge'))->assertOk()->assertHeader('X-Frame-Options', 'DENY');

    $this->flushHeaders()->postJson('/logout')->assertNoContent()->assertHeader('X-Frame-Options', 'DENY');
    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertUnprocessable()->assertHeader('X-Frame-Options', 'DENY');
});

/**
 * Keyring's routes, with a middleware of the app's inside Keyring's own
 * that sends these headers on every response.
 *
 * @param  array<string, string|list<string>>  $headers
 */
function withAppHeaders(array $headers): void
{
    Route::aliasMiddleware('app.headers', function (Request $request, Closure $next) use ($headers) {
        $response = $next($request);
        $response->headers->add($headers);

        return $response;
    });

    config(['keyring.middleware' => ['web', AddSecurityHeaders::class, 'app.headers']]);
    withFeatures(Features::all());
}

it('leaves framing to an app whose response already says who may frame it', function (array $headers, ?string $expected) {
    withAppHeaders($headers);

    $response = $this->inertia()->get('/login')->assertOk();

    expect($response->headers->get('X-Frame-Options'))->toBe($expected);
})->with([
    'a policy with frame-ancestors' => [['Content-Security-Policy' => "default-src 'self'; frame-ancestors 'self'"], null],
    'a policy that is only frame-ancestors' => [['Content-Security-Policy' => "frame-ancestors 'none'"], null],
    'a directive written in capitals' => [['Content-Security-Policy' => "default-src 'self';Frame-Ancestors https://example.com"], null],
    'the second of two policies' => [['Content-Security-Policy' => ["default-src 'self'", "frame-ancestors 'self'"]], null],
    'its own X-Frame-Options' => [['X-Frame-Options' => 'SAMEORIGIN'], 'SAMEORIGIN'],
]);

it('still refuses to be framed when the app\'s headers do not say who may', function (array $headers) {
    withAppHeaders($headers);

    $this->inertia()->get('/login')->assertOk()->assertHeader('X-Frame-Options', 'DENY');
})->with([
    'a policy without frame-ancestors' => [['Content-Security-Policy' => "default-src 'self'; script-src 'self'"]],
    'a source that only looks like the directive' => [['Content-Security-Policy' => "default-src 'self' https://frame-ancestors.example"]],
    'a policy that only reports' => [['Content-Security-Policy-Report-Only' => "frame-ancestors 'self'"]],
]);

// OWASP ASVS 5.0.0, 3.4.8: a page another site opened keeps no window in
// common with it. A popup the page opens itself still answers to it.
it('keeps its windows apart from the site that opened them, and keeps the popups it opens', function () {
    $this->inertia()->get('/login')->assertOk()->assertHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    $this->flushHeaders()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect()->assertHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
});

it('leaves the opener policy to an app that sends its own', function () {
    withAppHeaders(['Cross-Origin-Opener-Policy' => 'same-origin']);

    $this->inertia()->get('/login')->assertOk()->assertHeader('Cross-Origin-Opener-Policy', 'same-origin');
});

it('leaves caching to an app that takes the middleware out of the config', function () {
    config(['keyring.middleware' => ['web']]);
    withFeatures(Features::all());

    $this->get('/login')->assertHeaderMissing('Referrer-Policy')->assertHeaderMissing('X-Content-Type-Options')->assertHeaderMissing('X-Frame-Options')->assertHeaderMissing('Cross-Origin-Opener-Policy');
});

it('cycles the remember token when a device is revoked', function () {
    $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
    $token = $this->user->fresh()->remember_token;

    $device = Device::sole();
    $this->deleteJson(route('keyring.devices.destroy', $device->id));

    expect($this->user->fresh()->remember_token)->not->toBe($token);
});

it('keeps recognising two accounts that share a browser', function () {
    Event::fake([NewDeviceSignedIn::class]);
    User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    $abigail = fn (string $token) => test()->withHeader('User-Agent', FIREFOX)->withCookies(['known_device' => $token])
        ->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

    $token = deviceCookie(login());
    $this->post('/logout');
    $abigail($token);
    $this->post('/logout');
    $abigail($token);
    $this->post('/logout');
    login(['known_device' => $token]);

    Event::assertDispatchedTimes(NewDeviceSignedIn::class, 2);
    expect(Device::count())->toBe(2);
});

it('signs this session out when its own device is revoked', function () {
    $token = deviceCookie(login());

    $this->withCookie('known_device', $token)->withAssurance(Assurance::AAL1)
        ->delete(route('keyring.devices.destroy', Device::sole()->id))
        ->assertRedirect(route('login'));

    $this->assertGuest();
});

function requireSecondFactorUnlessTrusted(): void
{
    Keyring::require(fn (User $user, Attempt $attempt) => $attempt->device()?->isTrusted()
        ? Requirement::aal1()
        : Requirement::aal2()->ifEnrolled());
}

function trustThisDevice(Authenticator $totp, array $cookies = []): TestResponse
{
    login($cookies)->assertRedirect(route('keyring.login.challenge'));

    return test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret), 'trust' => true])
        ->assertRedirect('/dashboard');
}

describe('whose token a device gets', function () {
    beforeEach(function () {
        requireSecondFactorUnlessTrusted();
        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    });

    it('never stores a token nobody issued', function () {
        $planted = str_repeat('a', 40);

        $token = deviceCookie(trustThisDevice($this->totp, ['known_device' => $planted]));

        expect($token)->not->toBe($planted)
            ->and(Device::sole()->token_hash)->toBe(hash('sha256', $token));

        $this->post('/logout');

        login(['known_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
    });

    it('keeps trust away from a token planted from the attacker\'s own account', function () {
        // A real cookie the server issued to the attacker, planted in the
        // victim's browser. It's shared like any browser's cookie, so it
        // must not carry trust.
        User::create(['name' => 'Mallory', 'email' => 'mallory@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $planted = deviceCookie($this->withHeader('User-Agent', CHROME)
            ->post('/login', ['email' => 'mallory@example.com', 'password' => 'password']));
        $this->post('/logout');

        $victims = deviceCookie(trustThisDevice($this->totp, ['known_device' => $planted]));

        expect($victims)->not->toBe($planted)
            ->and($this->user->devices()->sole()->isTrusted())->toBeTrue();

        $this->post('/logout');

        login(['known_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();

        login(['known_device' => $victims])->assertRedirect('/dashboard');
    });

    it('moves everyone on a shared browser to the new token when one account trusts it', function () {
        Event::fake([NewDeviceSignedIn::class]);
        $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $shared = deviceCookie($this->withHeader('User-Agent', FIREFOX)
            ->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']));
        $this->post('/logout');

        $rotated = deviceCookie(trustThisDevice($this->totp, ['known_device' => $shared]));
        $this->post('/logout');

        expect($rotated)->not->toBe($shared);

        $this->withHeader('User-Agent', FIREFOX)->withCookie('known_device', $rotated)
            ->post('/login', ['email' => 'abigail@example.com', 'password' => 'password'])
            ->assertRedirect('/dashboard');

        // One each for the first sign ins, and none for the switch back.
        Event::assertDispatchedTimes(NewDeviceSignedIn::class, 2);
        expect(Device::count())->toBe(2)
            ->and($abigail->devices()->sole()->isTrusted())->toBeFalse();
    });

    it('rotates a known device\'s token when trust is granted and stops recognising the old one', function () {
        login()->assertRedirect(route('keyring.login.challenge'));
        $first = deviceCookie($this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)]));
        $this->post('/logout');

        login(['known_device' => $first])->assertRedirect(route('keyring.login.challenge'));
        $second = $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1), 'trust' => true]);

        expect(deviceCookie($second))->not->toBe($first)
            ->and(Device::sole()->token_hash)->toBe(hash('sha256', deviceCookie($second)));

        $this->post('/logout');

        login(['known_device' => $first])->assertRedirect(route('keyring.login.challenge'));
    });

    it('stops a planted token working once this account proves a second factor', function () {
        Keyring::require(fn (User $user, Attempt $attempt) => $attempt->isNewDevice() ? Requirement::aal2()->ifEnrolled() : Requirement::aal1());
        User::create(['name' => 'Mallory', 'email' => 'mallory@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $planted = deviceCookie($this->withHeader('User-Agent', CHROME)
            ->post('/login', ['email' => 'mallory@example.com', 'password' => 'password']));
        $this->post('/logout');

        login(['known_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
        $victims = deviceCookie($this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertRedirect('/dashboard'));

        expect($victims)->not->toBe($planted)
            ->and($this->user->devices()->sole()->token_hash)->toBe(hash('sha256', $victims));

        $this->post('/logout');

        login(['known_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
    });

    it('issues a new token on every login that proves a second factor, without trust', function () {
        login()->assertRedirect(route('keyring.login.challenge'));
        $first = deviceCookie($this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)]));
        $this->post('/logout');

        login(['known_device' => $first])->assertRedirect(route('keyring.login.challenge'));
        $second = deviceCookie($this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)]));

        expect($second)->not->toBe($first)
            ->and(Device::sole()->token_hash)->toBe(hash('sha256', $second));
    });
});

it('does not store a token nobody issued on a sign-in without trust', function () {
    $planted = str_repeat('a', 40);

    login(['known_device' => $planted])->assertRedirect('/dashboard');

    expect(Device::sole()->token_hash)->not->toBe(hash('sha256', $planted));
});

describe('earning trust', function () {
    it('never trusts a device after a password-only login', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'trust' => true])
            ->assertRedirect('/dashboard');

        expect(Device::sole()->trusted_until)->toBeNull();
    });

    it('waits for the second factor when trust is asked for with the password', function () {
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'trust' => true])
            ->assertRedirect(route('keyring.login.challenge'));

        expect(Device::count())->toBe(0);

        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');

        expect(Device::sole()->trusted_until)->not->toBeNull();
    });

    it('does not extend trust on a later login that only used the password', function () {
        requireSecondFactorUnlessTrusted();
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $token = deviceCookie(trustThisDevice($totp));
        $until = Device::sole()->trusted_until;
        $this->post('/logout');

        $this->travel(5)->days();

        $this->withHeader('User-Agent', FIREFOX)->withCookie('known_device', $token)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'trust' => true])
            ->assertRedirect('/dashboard');

        expect(Device::sole()->trusted_until->getTimestamp())->toBe($until->getTimestamp());
    });

    it('does not trust a device while the email address is unverified', function () {
        // Only signed in at all where registration signs new users in.
        revealTakenAddresses();
        $this->user->forceFill(['email_verified_at' => null])->save();
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        login();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret), 'trust' => true])->assertRedirect('/dashboard');

        expect(Device::sole()->trusted_until)->toBeNull();
    });

    it('trusts a device with an unverified email when the app does not verify emails', function () {
        revealTakenAddresses();
        withFeatures(array_values(array_diff(Features::all(), [Features::emailVerification()])));
        $this->user->forceFill(['email_verified_at' => null])->save();
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        login();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret), 'trust' => true])->assertRedirect('/dashboard');

        expect(Device::sole()->isTrusted())->toBeTrue();
    });
});

function expectNoTrustedDevices(): void
{
    expect(test()->user->devices()->whereNotNull('trusted_until')->exists())->toBeFalse();
}

describe('ending trust', function () {
    beforeEach(function () {
        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        trustThisDevice($this->totp);
        $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'elsewhere'), 'trusted_until' => now()->addDay()]);
    });

    it('stops trusting every device when an authenticator is removed', function () {
        $backup = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->deleteJson(route('keyring.authenticators.destroy', $backup->id))->assertOk();

        expectNoTrustedDevices();
    });

    it('stops trusting every device when the last second factor is removed', function () {
        config(['keyring.passwords.min_without_mfa' => 8]);

        $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id), ['password' => 'password'])->assertOk();

        expectNoTrustedDevices();
    });

    it('keeps trust while nothing was removed', function () {
        $this->patchJson(route('keyring.authenticators.update', $this->totp->id), ['name' => 'Phone'])->assertOk();

        expect($this->user->devices()->whereNotNull('trusted_until')->count())->toBe(2);
    });

    it('stops trusting every device when a one-per-user factor is replaced', function () {
        Keyring::factors([Password::class, Totp::class, EmailCode::asExtraStep(), RecoveryCodes::class]);
        Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'email-code', 'name' => 'Email', 'secret' => null]);

        app(AuthenticatorChanges::class)->add($this->user->fresh(), Keyring::factor('email-code'), new Authenticator(['factor' => 'email-code', 'name' => 'New email', 'secret' => null]));

        expectNoTrustedDevices();
    });

    it('keeps trust when recovery codes are regenerated', function () {
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();
        $factor = Keyring::factor('recovery');

        app(AuthenticatorChanges::class)->add($this->user->fresh(), $factor, $factor->make($factor->generate()['secret']));

        expect($this->user->devices()->whereNotNull('trusted_until')->count())->toBe(2);
    });

    it('stops trusting every device when an email change is applied', function () {
        $change = new PendingChange([
            'attribute' => 'email',
            'value' => 'new@example.com',
            'previous_value' => 'taylor@example.com',
            'confirm_token' => PendingChange::hashToken('confirm'),
            'revert_token' => PendingChange::hashToken('revert'),
            'expires_at' => now()->addDay(),
        ]);
        $change->authenticatable()->associate($this->user);
        $change->save();

        app(EmailChanges::class)->confirm($change, 'confirm');

        expect($this->user->fresh()->email)->toBe('new@example.com');
        expectNoTrustedDevices();
    });

    it('stops trusting every device when the password changes, even if other sessions stay', function () {
        $this->putJson(route('user-password.update'), [
            'current_password' => 'password',
            'password' => 'a much longer passphrase',
            'password_confirmation' => 'a much longer passphrase',
            'sign_out_others' => false,
        ])->assertOk();

        expectNoTrustedDevices();
    });

    it('stops trusting every device when a signed-in request locks the account', function () {
        Keyring::risk()->signals([riskySignal(Checkpoint::Request)])->respond(fn () => Action::allow()->lockFor('1h'));

        $this->get('/home')->assertOk();

        expect(app(RiskLocks::class)->locked($this->user))->toBeTrue();
        expectNoTrustedDevices();
    });

    it('keeps trusting devices when a login attempt locks the account', function () {
        Keyring::risk()->signals([riskySignal(Checkpoint::Login)])->respond(fn () => Action::deny()->lockFor('1h'));

        $this->post('/logout');
        login()->assertSessionHasErrors('email');

        expect(app(RiskLocks::class)->locked($this->user))->toBeTrue()
            ->and(Device::query()->whereNotNull('trusted_until')->exists())->toBeTrue();
    });
});

describe('ending other sessions along with a change to how the user signs in', function () {
    beforeEach(function () {
        Event::fake([SessionsRevoked::class]);

        /** Signed in here, having proved two factors, and on one other browser. */
        $this->signInTwice = function (string $driver = 'database') {
            config(['keyring.sessions.driver' => $driver]);

            $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->get('/home')->assertOk();
            $this->here = session(Sessions::KEY);

            $now = now()->getTimestamp();
            app(SessionRegistry::class)->save(new RegisteredSession('elsewhere', (string) $this->user->id, 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));
        };

        $this->expectOnlyThisSessionLeft = function () {
            $registry = app(SessionRegistry::class);

            expect($registry->find('elsewhere')->revokedAt)->not->toBeNull()
                ->and($registry->forUser($this->user)->map->id->all())->toBe([$this->here])
                ->and(session(Sessions::KEY))->toBe($this->here);

            Event::assertDispatched(SessionsRevoked::class, fn (SessionsRevoked $event) => $event->count === 1 && $event->user->is($this->user));
            $this->get('/home')->assertOk();
        };
    });

    it('ends them when adding an authenticator asks it to', function (string $driver) {
        ($this->signInTwice)($driver);

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');
        $id = session()->getId();

        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret), 'sign_out_others' => true])
            ->assertOk()
            ->assertJsonPath('status', 'authenticator-added');

        // This session carries on under a new ID, as after "sign out everywhere else".
        expect(session()->getId())->not->toBe($id)
            ->and($this->user->authenticators()->where('factor', 'totp')->count())->toBe(1);
        ($this->expectOnlyThisSessionLeft)();
    })->with('registries');

    it('ends them when removing an authenticator asks it to', function (string $driver) {
        ($this->signInTwice)($driver);
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $backup = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->deleteJson(route('keyring.authenticators.destroy', $backup->id), ['sign_out_others' => true])
            ->assertOk()
            ->assertJsonPath('status', 'authenticator-removed');

        expect($backup->fresh())->toBeNull();
        ($this->expectOnlyThisSessionLeft)();
    })->with('registries');

    it('ends them when new recovery codes ask it to', function () {
        ($this->signInTwice)();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $old = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'), ['sign_out_others' => true])->assertOk();

        expect($old->fresh())->toBeNull();
        ($this->expectOnlyThisSessionLeft)();
    });

    it('leaves them alone unless asked', function (array $data) {
        ($this->signInTwice)();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $backup = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret), ...$data])->assertOk();
        $this->deleteJson(route('keyring.authenticators.destroy', $backup->id), $data)->assertOk();

        expect(app(SessionRegistry::class)->find('elsewhere')->revokedAt)->toBeNull();
        Event::assertNotDispatched(SessionsRevoked::class);
    })->with([
        'nothing said' => [[]],
        'told not to' => [['sign_out_others' => false]],
    ]);

    it('changes nothing when the option makes no sense', function () {
        ($this->signInTwice)();
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $backup = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret), 'sign_out_others' => 'perhaps'])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('sign_out_others');
        $this->deleteJson(route('keyring.authenticators.destroy', $backup->id), ['sign_out_others' => 'perhaps'])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('sign_out_others');

        expect($this->user->authenticators()->count())->toBe(2)
            ->and(app(SessionRegistry::class)->find('elsewhere')->revokedAt)->toBeNull();
    });

    it('does not end them when the change itself was refused', function () {
        ($this->signInTwice)();
        $only = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        // The last second factor needs the password typed again.
        $this->deleteJson(route('keyring.authenticators.destroy', $only->id), ['sign_out_others' => true])->assertUnprocessable();

        expect($only->fresh())->not->toBeNull()
            ->and(app(SessionRegistry::class)->find('elsewhere')->revokedAt)->toBeNull();
    });
});

describe('signing out other sessions without the devices feature', function () {
    beforeEach(function () {
        withFeatures(array_values(array_diff(Features::all(), [Features::devices()])));
        Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
    });

    it('has a route of its own', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        Event::fake([SessionsRevoked::class]);
        $registry = app(SessionRegistry::class);

        expect(Route::has('keyring.devices.destroy-others'))->toBeFalse();

        login();
        $here = session(Sessions::KEY);
        $id = session()->getId();
        $now = now()->getTimestamp();
        $registry->save(new RegisteredSession('elsewhere', (string) $this->user->id, 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));
        $this->user->forceFill(['remember_token' => 'remembered'])->save();

        $this->deleteJson(route('keyring.sessions.destroy-others'))->assertOk()->assertJsonPath('status', 'sessions-revoked');

        expect($registry->find('elsewhere')->revokedAt)->not->toBeNull()
            ->and($registry->find($here)->revokedAt)->toBeNull()
            ->and($this->user->fresh()->remember_token)->not->toBe('remembered')
            ->and(session()->getId())->not->toBe($id);

        Event::assertDispatched(SessionsRevoked::class, fn (SessionsRevoked $event) => $event->count === 1);
        $this->get('/home')->assertOk();
    })->with('registries');

    it('needs a fresh verification', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour())
            ->deleteJson(route('keyring.sessions.destroy-others'))
            ->assertStatus(423);
    });

    it('is not there for a guest', function () {
        $this->deleteJson(route('keyring.sessions.destroy-others'))->assertUnauthorized();
    });
});

describe('the sessions a user can see and end', function () {
    beforeEach(function () {
        /** A session of the user's on another browser, last used a while ago. */
        $this->session = function (string $id, array $with = [], ?User $user = null): RegisteredSession {
            $now = now()->getTimestamp();

            return tap(
                new RegisteredSession($id, (string) ($user ?? $this->user)->id, 'web', null, Assurance::AAL1, '203.0.113.7', CHROME, $now - 600, $now - 300, $now + 3600)->with($with),
                fn (RegisteredSession $session) => app(SessionRegistry::class)->save($session),
            );
        };

        $this->handle = fn (string $id) => app(Sessions::class)->handle(app(SessionRegistry::class)->find($id));
    });

    it('lists every one of them, this one marked, whether or not devices are on', function (string $driver, array $features) {
        withFeatures($features);
        Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
        config(['keyring.sessions.driver' => $driver]);

        $this->freezeSecond();
        login();
        $here = app(SessionRegistry::class)->find(session(Sessions::KEY));
        $other = ($this->session)('elsewhere', ['remembered' => true]);

        $this->getJson(route('keyring.sessions.index'))
            ->assertOk()
            ->assertJsonCount(2, 'sessions')
            ->assertJsonPath('sessions.0', [
                'id' => app(Sessions::class)->handle($here),
                'name' => 'Firefox on Windows',
                'ip' => '127.0.0.1',
                'device' => $here->deviceId,
                'remembered' => false,
                'signedInAt' => now()->toIso8601String(),
                'lastActiveAt' => now()->toIso8601String(),
                'expiresAt' => now()->addDays(30)->toIso8601String(),
                'current' => true,
            ])
            ->assertJsonPath('sessions.1', [
                'id' => app(Sessions::class)->handle($other),
                'name' => 'Chrome on macOS',
                'ip' => '203.0.113.7',
                'device' => null,
                'remembered' => true,
                'signedInAt' => now()->subMinutes(10)->toIso8601String(),
                'lastActiveAt' => now()->subMinutes(5)->toIso8601String(),
                'expiresAt' => now()->addHour()->toIso8601String(),
                'current' => false,
            ]);
    })->with('registries')->with([
        'with devices' => [Features::all()],
        'without devices' => [array_values(array_diff(Features::all(), [Features::devices()]))],
        'with no features at all' => [[]],
    ]);

    it('shows a session that has no device, and two on one device apart', function () {
        $token = deviceCookie(login());
        $device = Device::sole()->id;
        $first = session(Sessions::KEY);

        $this->travel(1)->minutes();
        $this->flushSession();
        Auth::forgetGuards();
        login(['known_device' => $token]);

        ($this->session)('no-device');

        // The devices list has one row for all of it.
        $this->getJson(route('keyring.devices.index'))->assertJsonCount(1, 'devices')->assertJsonPath('devices.0.sessions', 2);

        $this->getJson(route('keyring.sessions.index'))
            ->assertJsonCount(3, 'sessions')
            ->assertJsonPath('sessions.0.device', $device)
            ->assertJsonPath('sessions.1.device', $device)
            ->assertJsonPath('sessions.1.id', ($this->handle)($first))
            ->assertJsonPath('sessions.2.device', null);

        // And one of the two on that device can be ended without the other.
        $this->deleteJson(route('keyring.sessions.destroy', ($this->handle)($first)))->assertOk();

        expect(app(SessionRegistry::class)->find($first)->revokedAt)->not->toBeNull();
        $this->get('/home')->assertOk();
    });

    it('leaves out sessions that have ended, idled out or moved to another record', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);
        login();

        ($this->session)('revoked');
        $registry->revoke('revoked');
        ($this->session)('expired', ['expiresAt' => now()->subMinute()->getTimestamp()]);
        ($this->session)('idle', ['lastActivityAt' => now()->subHours(3)->getTimestamp()]);
        $registry->replace('moved', ($this->session)('moved')->with(['id' => 'moved-on']));

        $this->getJson(route('keyring.sessions.index'))
            ->assertJsonCount(2, 'sessions')
            ->assertJsonPath('sessions.0.current', true)
            ->assertJsonPath('sessions.1.id', ($this->handle)('moved-on'));
    })->with('registries');

    it('never shows a registry ID, and the handle it shows is no use as one', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);

        $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
        $here = session(Sessions::KEY);
        ($this->session)(str_repeat('e', 40), ['remembered' => true]);

        $response = $this->getJson(route('keyring.sessions.index'))->assertOk();
        $handles = $response->json('sessions.*.id');

        expect($response->getContent())->not->toContain($here)->not->toContain(str_repeat('e', 40));

        foreach ($handles as $handle) {
            expect($handle)->toMatch('/^[0-9a-f]{64}$/')
                ->and(app(SessionRegistry::class)->find($handle))->toBeNull();
        }

        // The route that ends a session doesn't take the ID in the handle's
        // place, and it never reaches the log.
        $this->deleteJson('/user/sessions/'.str_repeat('e', 40))->assertNotFound();

        expect(app(SessionRegistry::class)->find(str_repeat('e', 40))->revokedAt)->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'access_refused')->exists())->toBeFalse();

        // And sent as the cookie that brings a remembered session back, a handle brings nothing.
        $user = $this->user->fresh();
        $recaller = [Auth::guard()->getRecallerName() => $user->id.'|'.$user->remember_token.'|'.$user->password];

        foreach ($handles as $handle) {
            $this->flushSession();
            Auth::forgetGuards();
            $this->withCookies([...$recaller, 'remembered_session' => $handle])->get('/home')->assertRedirect('/login');
            $this->assertGuest();
        }

        expect(app(SessionRegistry::class)->forUser($this->user)->map->id->all())->toEqualCanonicalizing([$here, str_repeat('e', 40)]);
    })->with('registries');

    it('ends one session and leaves the rest alone', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        Event::fake([SessionsRevoked::class]);
        $registry = app(SessionRegistry::class);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
        $here = session(Sessions::KEY);
        $token = $this->user->fresh()->remember_token;
        ($this->session)('phone');
        ($this->session)('tablet');

        $this->deleteJson(route('keyring.sessions.destroy', ($this->handle)('phone')))
            ->assertOk()
            ->assertJsonPath('status', 'session-revoked')
            ->assertJsonPath('message', 'That session has been signed out.');

        // Other remembered browsers keep their way back in.
        expect($registry->find('phone')->revokedAt)->not->toBeNull()
            ->and($registry->forUser($this->user)->map->id->all())->toEqualCanonicalizing([$here, 'tablet'])
            ->and($this->user->fresh()->remember_token)->toBe($token);

        Event::assertDispatched(SessionsRevoked::class, fn (SessionsRevoked $event) => $event->count === 1 && $event->user->is($this->user));
        $this->get('/home')->assertOk();

        // It's gone from the list, so its handle finds nothing now.
        $this->deleteJson(route('keyring.sessions.destroy', app(Sessions::class)->handle($registry->find('phone'))))->assertNotFound();
    })->with('registries');

    it('only ends the signed-in user\'s own', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        ($this->session)('theirs', user: $other);
        login();

        $this->getJson(route('keyring.sessions.index'))->assertJsonCount(1, 'sessions');

        $this->deleteJson(route('keyring.sessions.destroy', $handle = ($this->handle)('theirs')))->assertNotFound();

        // Asked for by its registry ID, it isn't even looked for.
        $this->deleteJson('/user/sessions/theirs')->assertNotFound();

        expect(app(SessionRegistry::class)->find('theirs')->revokedAt)->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'access_refused')->sole()->meta)->toEqual(['resource' => 'session', 'id' => $handle]);
    })->with('registries');

    it('signs out when the session it ends is this one', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        Event::fake([LoggedOut::class, SessionsRevoked::class]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
        $here = session(Sessions::KEY);
        $token = $this->user->fresh()->remember_token;
        ($this->session)('phone');

        // Exactly what POST /logout answers.
        $this->withCredentials()->withCookie('remembered_session', $here)
            ->deleteJson(route('keyring.sessions.destroy', ($this->handle)($here)))
            ->assertNoContent()
            ->assertHeader('Clear-Site-Data', '"cache", "storage"')
            ->assertCookieExpired('remembered_session');

        $this->assertGuest();
        expect(app(SessionRegistry::class)->find($here)->revokedAt)->not->toBeNull()
            ->and(app(SessionRegistry::class)->find('phone')->revokedAt)->toBeNull()
            ->and($this->user->fresh()->remember_token)->not->toBe($token)
            ->and(session()->has(Sessions::KEY))->toBeFalse();

        Event::assertDispatched(LoggedOut::class, fn (LoggedOut $event) => $event->user->is($this->user));
        Event::assertNotDispatched(SessionsRevoked::class);
    })->with('registries');

    it('sends a page visit that ended its own session where signing out does', function () {
        login();

        $this->delete(route('keyring.sessions.destroy', ($this->handle)(session(Sessions::KEY))))->assertRedirect('/');

        $this->assertGuest();
    });

    it('needs a fresh verification to end one, and none to look', function () {
        ($this->session)('phone');
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

        $this->getJson(route('keyring.sessions.index'))->assertOk()->assertJsonCount(2, 'sessions');
        $this->deleteJson(route('keyring.sessions.destroy', ($this->handle)('phone')))->assertStatus(423);

        expect(app(SessionRegistry::class)->find('phone')->revokedAt)->toBeNull();
    });

    it('is not there for a guest', function () {
        ($this->session)('phone');

        $this->getJson(route('keyring.sessions.index'))->assertUnauthorized();
        $this->deleteJson(route('keyring.sessions.destroy', ($this->handle)('phone')))->assertUnauthorized();
    });

    it('ends a session on the record "remember me" has carried it on to since', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $registry = app(SessionRegistry::class);

        $listed = ($this->session)('listed');
        $registry->replace('listed', $listed->with(['id' => 'carried-on']));

        app(Sessions::class)->revoke($this->user, $listed);

        expect($registry->find('carried-on')->revokedAt)->not->toBeNull()
            ->and($registry->forUser($this->user))->toBeEmpty();
    })->with('registries');

    it('gives each session a handle of its own, that changes with the app key', function () {
        $sessions = app(Sessions::class);
        $phone = ($this->session)('phone');
        $handle = $sessions->handle($phone);

        expect($sessions->handle(($this->session)('tablet')))->not->toBe($handle)
            ->and($sessions->handle($phone))->toBe($handle)
            ->and($sessions->find($this->user, $handle)->id)->toBe('phone');

        config(['app.key' => 'base64:'.base64_encode(random_bytes(32))]);

        expect($sessions->handle($phone))->not->toBe($handle);
    });
});

it('never queries the devices table when devices are off', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $backup = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    withFeatures(array_values(array_diff(Features::all(), [Features::devices()])));

    $queries = [];
    DB::listen(function ($query) use (&$queries) {
        $queries[] = $query->sql;
    });

    login()->assertRedirect(route('keyring.login.challenge'));
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret), 'authenticator' => $totp->id, 'trust' => true])->assertRedirect('/dashboard');
    $this->deleteJson(route('keyring.authenticators.destroy', $backup->id))->assertOk();
    app(Sessions::class)->distrustDevices($this->user);
    app(Sessions::class)->signOutEverywhere($this->user);

    expect($queries)->not->toBeEmpty()
        ->and(array_filter($queries, fn (string $sql) => str_contains($sql, 'keyring_devices')))->toBe([]);
});

function riskySignal(Checkpoint $checkpoint): Signal
{
    return new class($checkpoint) implements Signal
    {
        public function __construct(protected Checkpoint $checkpoint) {}

        public function assess(Assessment $assessment): Finding
        {
            return new Finding('always', 40, 'Always risky.');
        }

        public function checkpoints(): array
        {
            return [$this->checkpoint];
        }
    };
}
