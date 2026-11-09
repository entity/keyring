<?php

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\Signal;
use Keyring\Enums\Assurance;
use Keyring\Events\DeviceRevoked;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Features;
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
    $this->get('/home')->assertRedirect('/login')->assertHeader('Clear-Site-Data', '"cache", "storage"');

    expect(SecurityEvent::query()->where('type', 'session_ended')->sole()->meta)->toBe(['reason' => 'idle']);
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

        $token = deviceCookie(trustThisDevice($this->totp, ['keyring_device' => $planted]));

        expect($token)->not->toBe($planted)
            ->and(Device::sole()->token_hash)->toBe(hash('sha256', $token));

        $this->post('/logout');

        login(['keyring_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
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

        $victims = deviceCookie(trustThisDevice($this->totp, ['keyring_device' => $planted]));

        expect($victims)->not->toBe($planted)
            ->and($this->user->devices()->sole()->isTrusted())->toBeTrue();

        $this->post('/logout');

        login(['keyring_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();

        login(['keyring_device' => $victims])->assertRedirect('/dashboard');
    });

    it('moves everyone on a shared browser to the new token when one account trusts it', function () {
        Event::fake([NewDeviceSignedIn::class]);
        $abigail = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $shared = deviceCookie($this->withHeader('User-Agent', FIREFOX)
            ->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']));
        $this->post('/logout');

        $rotated = deviceCookie(trustThisDevice($this->totp, ['keyring_device' => $shared]));
        $this->post('/logout');

        expect($rotated)->not->toBe($shared);

        $this->withHeader('User-Agent', FIREFOX)->withCookie('keyring_device', $rotated)
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

        login(['keyring_device' => $first])->assertRedirect(route('keyring.login.challenge'));
        $second = $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1), 'trust' => true]);

        expect(deviceCookie($second))->not->toBe($first)
            ->and(Device::sole()->token_hash)->toBe(hash('sha256', deviceCookie($second)));

        $this->post('/logout');

        login(['keyring_device' => $first])->assertRedirect(route('keyring.login.challenge'));
    });

    it('stops a planted token working once this account proves a second factor', function () {
        Keyring::require(fn (User $user, Attempt $attempt) => $attempt->isNewDevice() ? Requirement::aal2()->ifEnrolled() : Requirement::aal1());
        User::create(['name' => 'Mallory', 'email' => 'mallory@example.com', 'password' => 'password', 'email_verified_at' => now()]);

        $planted = deviceCookie($this->withHeader('User-Agent', CHROME)
            ->post('/login', ['email' => 'mallory@example.com', 'password' => 'password']));
        $this->post('/logout');

        login(['keyring_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
        $victims = deviceCookie($this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertRedirect('/dashboard'));

        expect($victims)->not->toBe($planted)
            ->and($this->user->devices()->sole()->token_hash)->toBe(hash('sha256', $victims));

        $this->post('/logout');

        login(['keyring_device' => $planted])->assertRedirect(route('keyring.login.challenge'));
        $this->assertGuest();
    });

    it('issues a new token on every login that proves a second factor, without trust', function () {
        login()->assertRedirect(route('keyring.login.challenge'));
        $first = deviceCookie($this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)]));
        $this->post('/logout');

        login(['keyring_device' => $first])->assertRedirect(route('keyring.login.challenge'));
        $second = deviceCookie($this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)]));

        expect($second)->not->toBe($first)
            ->and(Device::sole()->token_hash)->toBe(hash('sha256', $second));
    });
});

it('does not store a token nobody issued on a sign-in without trust', function () {
    $planted = str_repeat('a', 40);

    login(['keyring_device' => $planted])->assertRedirect('/dashboard');

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

        $this->withHeader('User-Agent', FIREFOX)->withCookie('keyring_device', $token)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'trust' => true])
            ->assertRedirect('/dashboard');

        expect(Device::sole()->trusted_until->getTimestamp())->toBe($until->getTimestamp());
    });

    it('does not trust a device while the email address is unverified', function () {
        $this->user->forceFill(['email_verified_at' => null])->save();
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        login();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret), 'trust' => true])->assertRedirect('/dashboard');

        expect(Device::sole()->trusted_until)->toBeNull();
    });

    it('trusts a device with an unverified email when the app does not verify emails', function () {
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
        Keyring::factors([Password::class, Totp::class, EmailCode::asSecondFactor(), RecoveryCodes::class]);
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

    it('stops trusting every device when the account is locked', function () {
        Keyring::risk([new class implements Signal
        {
            public function assess(Assessment $assessment): Finding
            {
                return new Finding('always', 40, 'Always risky.');
            }

            public function checkpoints(): array
            {
                return [Checkpoint::Login];
            }
        }])->respond(fn () => Action::deny()->lockFor('1h'));

        $this->post('/logout');
        login()->assertSessionHasErrors('email');

        expectNoTrustedDevices();
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
    app(Sessions::class)->revokeAll($this->user);

    expect($queries)->not->toBeEmpty()
        ->and(array_filter($queries, fn (string $sql) => str_contains($sql, 'keyring_devices')))->toBe([]);
});
