<?php

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Events\DeviceRevoked;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
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
    return $response->getCookie('keyring_device')->getValue();
}

dataset('registries', ['database', 'cache']);

it('remembers devices and announces new ones', function () {
    Event::fake([NewDeviceSignedIn::class]);

    $response = login()->assertCookie('keyring_device');
    $token = deviceCookie($response);

    $device = Device::sole();
    expect($device->name)->toBe('Firefox on Windows')
        ->and($device->token_hash)->toBe(hash('sha256', $token));

    Event::assertDispatchedTimes(NewDeviceSignedIn::class, 1);

    $this->post('/logout');
    login(['keyring_device' => $token]);

    Event::assertDispatchedTimes(NewDeviceSignedIn::class, 1);
    expect(Device::count())->toBe(1);
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
    $this->inertia()->get($url)->assertOk()->assertJsonPath('component', 'auth/device-report');
    $this->flushHeaders();
    expect(Device::sole()->isRevoked())->toBeFalse();

    $this->post($url)->assertRedirect('/login');

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

    login(['keyring_device' => $token])->assertRedirect('/dashboard');
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

    app(Sessions::class)->revokeAll($this->user);

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
    $this->get('/home')->assertRedirect('/login');
});

it('registers sessions that started some other way', function () {
    $this->actingAs($this->user)->get('/home')->assertOk();

    expect(app(SessionRegistry::class)->forUser($this->user))->toHaveCount(1);
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

    $abigail = fn (string $token) => test()->withHeader('User-Agent', FIREFOX)->withCookies(['keyring_device' => $token])
        ->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

    $token = deviceCookie(login());
    $this->post('/logout');
    $abigail($token);
    $this->post('/logout');
    $abigail($token);
    $this->post('/logout');
    login(['keyring_device' => $token]);

    Event::assertDispatchedTimes(NewDeviceSignedIn::class, 2);
    expect(Device::count())->toBe(2);
});

it('signs this session out when its own device is revoked', function () {
    $token = deviceCookie(login());

    $this->withCookie('keyring_device', $token)->withAssurance(Assurance::AAL1)
        ->delete(route('keyring.devices.destroy', Device::sole()->id))
        ->assertRedirect(route('login'));

    $this->assertGuest();
});
