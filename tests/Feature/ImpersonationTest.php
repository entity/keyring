<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Login;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Session\Middleware\AuthenticateSession as LaravelAuthenticateSession;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Keyring\Changes\PasswordHolds;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\ImpersonationEndReason;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\Authenticated;
use Keyring\Events\ImpersonationEnded;
use Keyring\Events\ImpersonationStarted;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Events\RegisteredSessionEnded;
use Keyring\Exceptions\ImpersonationRefused;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Impersonation\Impersonation;
use Keyring\KeyringManager;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\PlainFormRequest;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Route::middleware(['web', 'auth'])->get('/whoami', fn () => (string) Auth::id());
    Route::middleware('web')->get('/welcome', fn () => Auth::check() ? (string) Auth::id() : 'guest');
    Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
    Route::middleware(['web', 'auth', 'keyring.not-impersonating'])->delete('/account', fn () => 'deleted');

    $this->admin = taylor(['name' => 'Ada Admin', 'email' => 'admin@example.com']);
    $this->totp = Authenticator::factory()->totp()->for($this->admin, 'authenticatable')->create();
    $this->user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    Keyring::allowImpersonationWhen(fn (User $impersonator, User $user) => $impersonator->is($this->admin));
});

/**
 * The admin signs in with their password and authenticator app, so their
 * session has just proved two factors.
 */
function adminSignsIn(bool $remember = false): void
{
    test()->post('/login', ['email' => 'admin@example.com', 'password' => 'password', 'remember' => $remember]);
    test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode(test()->totp->secret)])->assertRedirect('/dashboard');
}

function impersonate(Model $user, bool $json = false): TestResponse
{
    $url = route('keyring.impersonation.store', $user->getKey());

    return $json ? test()->postJson($url) : test()->post($url);
}

function stopImpersonating(bool $json = false): TestResponse
{
    return $json ? test()->deleteJson(route('keyring.impersonation.destroy')) : test()->delete(route('keyring.impersonation.destroy'));
}

/**
 * The admin, signed in, impersonating the user. Returns the registry ID of
 * the admin's own session.
 */
function impersonating(): string
{
    adminSignsIn();
    $own = session(Sessions::KEY);

    impersonate(test()->user)->assertRedirect('/dashboard');

    return $own;
}

function record(string $id): ?RegisteredSession
{
    return app(SessionRegistry::class)->find($id);
}

/**
 * Keep the session on Laravel's cookie driver, which lives in the browser.
 */
function onTheCookieDriver(): void
{
    config(['session.driver' => 'cookie']);
    app('session')->forgetDrivers();
    app()->forgetInstance('session.store');
}

/**
 * The cookies a cookie session is in, after a response: its ID, and the
 * session itself under that name.
 *
 * @return array<string, string>
 */
function cookiesOf(TestResponse $response): array
{
    $id = $response->getCookie(config('session.cookie'))->getValue();

    return [config('session.cookie') => $id, $id => $response->getCookie($id)->getValue()];
}

describe('who may impersonate', function () {
    it('signs in as the user once the callback says so', function () {
        adminSignsIn();

        impersonate($this->user)->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-started');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey())
            ->and(Keyring::impersonating())->toBeTrue()
            ->and(Keyring::impersonator()->is($this->admin))->toBeTrue();
    });

    it('refuses everyone until the app says who may', function () {
        (fn () => $this->impersonationGate = null)->call(app(KeyringManager::class));
        adminSignsIn();

        impersonate($this->user)->assertForbidden();

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(Keyring::allowsImpersonation($this->admin, $this->user))->toBeFalse();
    });

    it('refuses whoever the callback turns down, and asks it with the impersonator and the user', function () {
        $asked = [];
        Keyring::allowImpersonationWhen(function (User $impersonator, User $user) use (&$asked) {
            $asked = [$impersonator->getKey(), $user->getKey()];

            return false;
        });
        adminSignsIn();

        impersonate($this->user, json: true)->assertForbidden()->assertJson(['message' => __('keyring::keyring.impersonation_refused')]);

        expect($asked)->toBe([$this->admin->getKey(), $this->user->getKey()]);
    });

    it('only counts a callback that answers true', function () {
        Keyring::allowImpersonationWhen(fn () => 1);

        expect(Keyring::allowsImpersonation($this->admin, $this->user))->toBeFalse();
    });

    it('has no routes, and refuses in code, with the feature off', function () {
        withFeatures(array_values(array_diff(Features::all(), [Features::impersonation()])));
        adminSignsIn();

        $this->post('/impersonate/'.$this->user->getKey())->assertNotFound();

        expect(Route::has('keyring.impersonation.store'))->toBeFalse()
            ->and(Route::has('keyring.impersonation.destroy'))->toBeFalse()
            ->and(Keyring::allowsImpersonation($this->admin, $this->user))->toBeFalse()
            ->and(fn () => Keyring::impersonate(request(), $this->user))->toThrow(ImpersonationRefused::class);
    });

    it('refuses impersonating yourself', function () {
        Keyring::allowImpersonationWhen(fn () => true);
        adminSignsIn();

        impersonate($this->admin)->assertForbidden();

        try {
            Keyring::impersonate(request(), $this->admin);
        } catch (ImpersonationRefused $e) {
        }

        expect($e->reason)->toBe('self');
    });

    it('refuses a user the app does not let sign in', function () {
        Keyring::allowSignInWhen(fn (User $user) => ! $user->is($this->user));
        adminSignsIn();

        impersonate($this->user)->assertForbidden();
    });

    it('refuses an ID nobody has as it refuses one it may not impersonate', function () {
        adminSignsIn();

        impersonate(new User(['id' => 999]), json: true)->assertForbidden()->assertJson(['message' => __('keyring::keyring.impersonation_refused')]);
    });

    it('refuses an account of another model, which the guard would not load', function () {
        Keyring::allowImpersonationWhen(fn () => true);

        expect(Keyring::allowsImpersonation($this->admin, staff()))->toBeFalse();
    });

    it('refuses a session keyring has no record of, which there would be no coming back to', function () {
        Route::middleware(['web', 'auth'])->post('/become/{id}', function (Request $request, string $id) {
            $request->session()->forget(Sessions::KEY);

            try {
                Keyring::impersonate($request, User::findOrFail($id));
            } catch (ImpersonationRefused $e) {
                return $e->reason;
            }
        });
        adminSignsIn();

        expect($this->post('/become/'.$this->user->getKey())->getContent())->toBe('unregistered');
    });
});

describe('starting', function () {
    it('needs two factors proved in the last 15 minutes', function () {
        adminSignsIn();
        $this->travel(16)->minutes();

        impersonate($this->user)->assertRedirect(route('keyring.confirm.challenge'));

        expect(Keyring::impersonating())->toBeFalse();
    });

    it('needs a second factor, whatever the password proved', function () {
        $this->totp->delete();
        $this->post('/login', ['email' => 'admin@example.com', 'password' => 'password']);

        impersonate($this->user, json: true)->assertForbidden()->assertJson(['status' => 'enroll-first']);

        expect(Keyring::impersonating())->toBeFalse();
    });

    it('is only a POST', function () {
        adminSignsIn();

        $this->get('/impersonate/'.$this->user->getKey())->assertMethodNotAllowed();

        expect(Keyring::impersonating())->toBeFalse();
    });

    it('is one at a time', function () {
        $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        impersonating();

        impersonate($other, json: true)->assertForbidden()->assertJson(['status' => 'impersonating']);

        try {
            Keyring::impersonate(request(), $other);
        } catch (ImpersonationRefused $e) {
        }

        expect($e->reason)->toBe('impersonating')
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    });

    it('gives the browser a new session id, and the user a session record of their own', function () {
        adminSignsIn();
        $before = session()->getId();
        $own = session(Sessions::KEY);

        impersonate($this->user);
        $record = record(session(Sessions::KEY));

        expect(session()->getId())->not->toBe($before)
            ->and($record->belongsTo($this->user))->toBeTrue()
            ->and($record->isImpersonated())->toBeTrue()
            ->and($record->impersonatorId)->toBe((string) $this->admin->getKey())
            ->and($record->impersonatorType)->toBe(RegisteredSession::typeOf($this->admin))
            ->and($record->impersonatorSession)->toBe($own)
            ->and($record->remembered)->toBeFalse()
            ->and($record->deviceId)->toBeNull()
            ->and($record->expiresAt)->toBe(now()->addHour()->getTimestamp())
            // The admin's own session is parked, not ended.
            ->and(record($own)->isActive(now()->getTimestamp()))->toBeTrue();
    });

    it('is not the user signing in: no sign in events, no new device, no emails', function () {
        adminSignsIn();
        Event::fake([Login::class, Authenticated::class, NewDeviceSignedIn::class]);
        Notification::fake();

        impersonate($this->user);

        Event::assertNotDispatched(Login::class);
        Event::assertNotDispatched(Authenticated::class);
        Event::assertNotDispatched(NewDeviceSignedIn::class);
        Notification::assertNothingSent();
        expect(SecurityEvent::query()->whereMorphedTo('authenticatable', $this->user)->pluck('type')->all())->toBe(['impersonation_started']);
    });

    it('carries nothing the admin proved over to the user', function () {
        adminSignsIn();
        session()->put('auth.password_confirmed_at', now()->getTimestamp());

        impersonate($this->user);

        expect(session(SessionAssurance::KEY))->toBeNull()
            ->and(session('auth.password_confirmed_at'))->toBeNull()
            ->and(app(SessionAssurance::class)->level()->name)->toBe('None')
            ->and(record(session(Sessions::KEY))->assurance->name)->toBe('None');
    });

    // Laravel's auth.session middleware keeps the signed-in user's password
    // hash in the session, and signs out a session whose hash no longer
    // matches. The admin's isn't carried over to be compared with the user's.
    it('keeps the user signed in through laravel\'s auth.session middleware, and the admin after', function () {
        Route::middleware(['web', 'auth', LaravelAuthenticateSession::class])->get('/checked', fn () => (string) Auth::id());
        adminSignsIn();
        $this->get('/checked');

        impersonate($this->user);

        expect($this->get('/checked')->assertOk()->getContent())->toBe((string) $this->user->getKey());

        stopImpersonating();

        expect($this->get('/checked')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });

    it('can\'t prove anything as the user', function () {
        impersonating();

        $this->get('/billing')->assertForbidden();
        $this->getJson('/billing')->assertForbidden()->assertJson(['status' => 'impersonating', 'message' => Keyring::statusMessage('impersonating')]);
        $this->get(route('keyring.confirm.challenge'))->assertForbidden();
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertForbidden();
    });

    it('answers json clients with its status and where to go', function () {
        adminSignsIn();

        impersonate($this->user, json: true)->assertOk()->assertJson([
            'status' => 'impersonation-started',
            'message' => Keyring::statusMessage('impersonation-started'),
            'redirect' => url('/dashboard'),
        ])->assertHeader('Clear-Site-Data', '"cache", "storage"');
    });

    it('goes to impersonation.redirect_to', function () {
        config(['keyring.impersonation.redirect_to' => '/support/view']);
        adminSignsIn();

        impersonate($this->user)->assertRedirect('/support/view');
    });

    it('lasts no longer than the session could', function () {
        config(['keyring.impersonation.lifetime' => '90d']);
        adminSignsIn();

        impersonate($this->user);

        expect(record(session(Sessions::KEY))->expiresAt)->toBe(now()->addDays(30)->getTimestamp());
    });
});

describe('while impersonating', function () {
    it('refuses keyring\'s security changes', function (string $method, Closure $url, array $data = []) {
        impersonating();
        $this->user->update(['remember_token' => 'the users own']);

        $this->json($method, $url(), $data)->assertForbidden()->assertJson(['status' => 'impersonating']);

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    })->with([
        'changing the password' => ['PUT', fn () => route('user-password.update'), ['current_password' => 'password', 'password' => 'a much longer passphrase', 'password_confirmation' => 'a much longer passphrase']],
        'changing the email address' => ['POST', fn () => route('keyring.email.store'), ['email' => 'new@example.com']],
        'cancelling an email change' => ['DELETE', fn () => route('keyring.email.destroy')],
        'adding an authenticator' => ['POST', fn () => route('keyring.authenticators.store', 'totp')],
        'confirming an authenticator' => ['POST', fn () => route('keyring.authenticators.confirm', 'totp'), ['code' => '123456']],
        'renaming an authenticator' => ['PATCH', fn () => route('keyring.authenticators.update', 'anything'), ['name' => 'Mine']],
        'removing an authenticator' => ['DELETE', fn () => route('keyring.authenticators.destroy', 'anything')],
        'signing out everywhere else' => ['DELETE', fn () => route('keyring.sessions.destroy-others')],
        'ending a session' => ['DELETE', fn () => route('keyring.sessions.destroy', str_repeat('a', 64))],
        'signing out other devices' => ['DELETE', fn () => route('keyring.devices.destroy-others')],
        'signing out a device' => ['DELETE', fn () => route('keyring.devices.destroy', 'anything')],
        'confirming it\'s them' => ['POST', fn () => route('keyring.confirm.verify', 'password'), ['password' => 'password']],
        'the confirm page' => ['GET', fn () => route('keyring.confirm.challenge')],
    ]);

    it('refuses the app\'s own routes behind keyring.not-impersonating, and lets them through otherwise', function () {
        adminSignsIn();
        $this->delete('/account')->assertOk();

        impersonate($this->user);

        $this->delete('/account')->assertForbidden();
        $this->deleteJson('/account')->assertForbidden()->assertExactJson(['status' => 'impersonating', 'message' => Keyring::statusMessage('impersonating')]);
    });

    it('lets the user\'s sessions be listed', function () {
        impersonating();

        $sessions = $this->getJson(route('keyring.sessions.index'))->assertOk()->json('sessions');

        expect($sessions)->toHaveCount(1)
            ->and($sessions[0])->toMatchArray(['current' => true, 'impersonated' => true, 'impersonator' => 'Ada Admin']);
    });

    it('is not held to what the user has still to do: enroll, or change a held password', function () {
        Route::middleware(['web', 'auth', 'keyring.enrolled', 'keyring.password'])->get('/orders', fn () => 'orders');
        config(['keyring.enrollment_url' => '/enroll', 'keyring.password_change_url' => '/change-password']);
        app(PasswordHolds::class)->place($this->user);

        impersonating();

        $this->get('/orders')->assertOk()->assertSee('orders');
    });

    it('shares what a banner needs', function () {
        $this->freezeSecond();
        impersonating();

        expect(Keyring::impersonation())->toBe([
            'impersonator' => ['id' => (string) $this->admin->getKey(), 'name' => 'Ada Admin'],
            'startedAt' => now()->toIso8601String(),
            'expiresAt' => now()->addHour()->toIso8601String(),
            'stopUrl' => route('keyring.impersonation.destroy'),
        ]);
    });

    it('shares nothing, and nobody, when nobody is impersonating', function () {
        adminSignsIn();

        expect(Keyring::impersonation())->toBeNull()
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(Keyring::impersonator())->toBeNull();
    });

    it('keeps the admin\'s own session from idling out while they\'re busy', function () {
        config(['keyring.impersonation.lifetime' => '4h']);
        $own = impersonating();

        foreach (range(1, 3) as $hour) {
            $this->travel(50)->minutes();
            $this->get('/whoami')->assertOk();
        }

        expect(Keyring::impersonating())->toBeTrue()
            ->and(record($own)->lastActivityAt)->toBe(now()->getTimestamp())
            ->and(record(session(Sessions::KEY))->lastActivityAt)->toBe(now()->getTimestamp())
            ->and(record(session(Sessions::KEY))->impersonatorSession)->toBe($own);
    });

    it('doesn\'t take one of the user\'s places under sessions.max, nor end one to make room', function () {
        config(['keyring.sessions.max' => 2]);
        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);
        $users = session(Sessions::KEY);
        $this->flushSession();
        Auth::forgetGuards();
        $this->travel(1)->minutes();

        impersonating();
        $impersonated = session(Sessions::KEY);
        $admin = session()->all();
        $this->flushSession();
        Auth::forgetGuards();

        // The user signs in somewhere else: with two places, both their own stay.
        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

        expect(record($users)->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(record($impersonated)->isActive(now()->getTimestamp()))->toBeTrue();

        sendBackSession($admin);

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    });

    it('isn\'t the session that ends to make room under sessions.max, even having gone unused longest', function () {
        config(['keyring.sessions.max' => 2]);
        impersonating();
        $impersonated = session(Sessions::KEY);
        $admin = session()->all();

        $own = array_map(function () {
            $this->flushSession();
            Auth::forgetGuards();
            $this->travel(1)->minutes();
            $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

            return session(Sessions::KEY);
        }, range(1, 3));

        // The third sign in takes them past two: their own oldest ends.
        expect(record($own[0])->revokedAt)->not->toBeNull()
            ->and(record($own[1])->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(record($own[2])->isActive(now()->getTimestamp()))->toBeTrue()
            ->and(record($impersonated)->isActive(now()->getTimestamp()))->toBeTrue();

        sendBackSession($admin);

        expect($this->get('/whoami')->getContent())->toBe((string) $this->user->getKey());
    });
});

describe('stopping', function () {
    it('goes back to the admin\'s own session, with what it had proved, on a new session id', function () {
        $own = impersonating();
        $impersonated = session(Sessions::KEY);
        $before = session()->getId();

        stopImpersonating()->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');

        expect(session()->getId())->not->toBe($before)
            ->and(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(Keyring::impersonating())->toBeFalse()
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(record(session(Sessions::KEY))->revokedAt)->toBeNull();

        // AAL2 from the admin's own sign in, without a confirm.
        $this->get('/billing')->assertOk()->assertSee('billing');
    });

    it('answers json clients, and goes to impersonation.return_to', function () {
        config(['keyring.impersonation.return_to' => '/admin/users']);
        impersonating();

        stopImpersonating(json: true)->assertOk()->assertJson([
            'status' => 'impersonation-ended',
            'redirect' => url('/admin/users'),
        ])->assertHeader('Clear-Site-Data', '"cache", "storage"');
    });

    it('is a POST too, for a plain form', function () {
        impersonating();

        $this->post(route('keyring.impersonation.destroy'))->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('is not found when nobody is being impersonated', function () {
        adminSignsIn();

        stopImpersonating()->assertNotFound();

        expect(fn () => Keyring::stopImpersonating(request()))->toThrow(LogicException::class);
    });

    it('signs out when there is no going back', function (Closure $meanwhile) {
        $own = impersonating();
        $meanwhile->call($this, $own);

        stopImpersonating(json: true)->assertUnauthorized()->assertJson(['status' => 'signed-out']);

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)?->isActive(now()->getTimestamp()) ?? false)->toBeFalse();
        $this->get('/whoami')->assertRedirect('/login');
    })->with([
        'the admin\'s session was revoked' => [fn (string $own) => app(SessionRegistry::class)->revoke($own)],
        'the admin\'s session is gone' => [function (string $own) {
            app(SessionRegistry::class)->revoke($own);
            app(SessionRegistry::class)->prune();
        }],
        'the admin was deleted' => [fn () => $this->admin->delete()],
        'the admin may no longer sign in' => [fn () => Keyring::allowSignInWhen(fn (User $user) => ! $user->is($this->admin))],
        'the admin\'s session expired' => [fn (string $own) => app(SessionRegistry::class)->update($own, ['expiresAt' => now()->getTimestamp()])],
        'the admin\'s session idled out' => [fn (string $own) => app(SessionRegistry::class)->update($own, ['lastActivityAt' => now()->subHours(3)->getTimestamp()])],
        'the admin is held for a new password' => [fn () => app(PasswordHolds::class)->place($this->admin)],
    ]);

    // The session middleware ends an impersonation it finds over before
    // the request gets this far. One that ends while the request is under
    // way still signs out.
    it('signs out when the admin\'s session ends while the request is under way', function () {
        $own = impersonating();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        app(SessionRegistry::class)->revoke($own);

        stopImpersonating(json: true)->assertUnauthorized()->assertJson(['status' => 'signed-out']);

        expect(Auth::guard('web')->check())->toBeFalse();
    });

    it('leaves the admin\'s "remember me" cookies as they are, and remembered, moving keyring\'s with their record', function () {
        adminSignsIn(remember: true);
        $own = session(Sessions::KEY);
        $recaller = Auth::guard('web')->getRecallerName();

        Cookie::flushQueuedCookies();
        $started = impersonate($this->user);
        Cookie::flushQueuedCookies();
        $stopped = stopImpersonating();

        expect($started->getCookie($recaller))->toBeNull()
            ->and($started->getCookie('remembered_session'))->toBeNull()
            ->and($stopped->getCookie($recaller))->toBeNull()
            ->and($stopped->getCookie('remembered_session')->getValue())->toBe(session(Sessions::KEY))
            ->and(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and(session(Sessions::REMEMBERED))->toBeTrue()
            ->and(record(session(Sessions::KEY))->remembered)->toBeTrue();
    });

    // A request sent while impersonating that saves its copy of the session
    // after the stop would put back what was parked, on any session driver.
    it('leaves a request that overlapped the stop nothing to go back to', function () {
        $own = impersonating();
        $during = session()->all();

        stopImpersonating()->assertRedirect('/dashboard');

        expect(record($own)->revokedAt)->not->toBeNull()
            ->and(record($own)->replacedBy)->toBe(session(Sessions::KEY));

        sendBackSession($during);
        $this->getJson('/whoami')->assertUnauthorized();

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record(record($own)->replacedBy)->revokedAt)->toBeNull();
    });

    it('works on either registry', function (string $driver) {
        config(['keyring.sessions.driver' => $driver]);
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        stopImpersonating();

        expect(record($impersonated)->impersonatorSession)->toBe($own)
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(session(Sessions::KEY))->toBe(record($own)->replacedBy);
    })->with(['database', 'cache']);

    // A page of the user's could have sent the stop, a stored script say,
    // and would then act as an admin who had just proved everything.
    it('comes back at the admin\'s level, with nothing counting as fresh', function () {
        Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/danger', fn () => 'danger zone');
        impersonating();

        stopImpersonating();

        $this->get('/billing')->assertOk()->assertSee('billing');
        $this->get('/danger')->assertRedirect(route('keyring.confirm.challenge'));
        $this->getJson('/danger')->assertStatus(423);

        expect(app(SessionAssurance::class)->level()->name)->toBe('AAL2')
            ->and(app(SessionAssurance::class)->provedSince(now()->subMinutes(15)->getTimestamp()))->toBe([]);
    });

    // The admin's own session would lapse a level after a gap past its idle
    // limit. Impersonating meanwhile doesn't wipe the gap out.
    it('lapses a level whose idle limit passed between two requests, as the admin\'s own session would', function () {
        config(['keyring.sessions.levels.aal2.idle' => '30m']);
        impersonating();

        $this->travel(20)->minutes();
        $this->get('/whoami')->assertOk();
        $this->travel(40)->minutes();

        stopImpersonating()->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('lapses each level on its own clock: aal3 after 15 minutes, aal2 after an hour', function (int $gap, Assurance $level) {
        $this->actingAs($this->admin)->withAssurance(Assurance::AAL3);
        $this->get('/whoami')->assertOk();
        impersonate($this->user)->assertRedirect('/dashboard');

        $this->travel($gap)->minutes();
        stopImpersonating()->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe($level);
    })->with([
        'a 10 minute gap' => [10, Assurance::AAL3],
        'a 20 minute gap' => [20, Assurance::AAL2],
    ]);

    it('ends the admin\'s session where sessions end with their level, when a gap lapses it', function () {
        config(['keyring.sessions.end_on_lapse' => true, 'keyring.sessions.levels.aal2.idle' => '30m']);
        $own = impersonating();

        $this->travel(40)->minutes();

        $this->get('/whoami')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['impersonator_session_ended']);
    });

    // Without the session middleware getting there first, the stop itself
    // finds the level gone.
    it('ends it on a stop of the app\'s own too', function () {
        config(['keyring.sessions.end_on_lapse' => true, 'keyring.sessions.levels.aal2.idle' => '30m']);
        $own = impersonating();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);

        $this->travel(40)->minutes();

        stopImpersonating(json: true)->assertUnauthorized();

        expect(record($own)->revokedAt)->not->toBeNull();
    });

    // A form request is a copy of request(), which the Logout listener reads.
    it('announces a stop that signs out once, given a form request', function () {
        $own = impersonating();
        Route::middleware(['web', 'auth'])->delete('/admin/impersonation', function (PlainFormRequest $request) use ($own) {
            app(SessionRegistry::class)->revoke($own);

            return Keyring::stopImpersonating($request) === null ? 'signed out' : 'back';
        });
        Event::fake([ImpersonationEnded::class]);

        expect($this->delete('/admin/impersonation')->getContent())->toBe('signed out')
            ->and(Auth::guard('web')->check())->toBeFalse();
        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::ImpersonatorSessionEnded);
    });

    // Laravel's auth.session middleware would sign them out on its own, but
    // only where it runs, and its step after the response stores the
    // current hash over the one put back. Keyring compares them itself.
    it('signs the admin out rather than going back, when their password changed meanwhile', function () {
        Route::middleware(['web', 'auth', LaravelAuthenticateSession::class])->get('/checked', fn () => (string) Auth::id());
        adminSignsIn();
        $this->get('/checked');
        $own = session(Sessions::KEY);
        impersonate($this->user);
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);

        // Saved behind Keyring's back, so nothing else signs the admin out.
        User::query()->whereKey($this->admin->getKey())->update(['password' => Hash::make('changed somewhere else')]);

        stopImpersonating()->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['impersonator_session_ended']);
        $this->get('/checked')->assertRedirect('/login');
    });

    it('signs the admin out on a stop that laravel\'s auth.session middleware wraps, when their password changed meanwhile', function (Closure $change) {
        app('router')->pushMiddlewareToGroup('web', LaravelAuthenticateSession::class);
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);
        $own = impersonating();
        $this->get('/whoami')->assertOk();

        $change($this->admin);
        Auth::forgetGuards();

        stopImpersonating()->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
        Auth::forgetGuards();
        $this->get('/whoami')->assertRedirect('/login');
        $this->get('/billing')->assertRedirect('/login');
    })->with([
        'with the query builder' => [fn (User $admin) => User::query()->whereKey($admin->getKey())->update(['password' => Hash::make('changed somewhere else')])],
        'without keyring\'s protection' => [fn (User $admin) => Keyring::withoutProtection(fn () => $admin->fresh()->forceFill(['password' => Hash::make('changed somewhere else')])->save())],
    ]);

    it('goes back as before when laravel\'s auth.session middleware wraps the stop and the password is the same', function () {
        app('router')->pushMiddlewareToGroup('web', LaravelAuthenticateSession::class);
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);
        $own = impersonating();
        $this->get('/whoami')->assertOk();
        Auth::forgetGuards();

        stopImpersonating()->assertRedirect('/dashboard');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy);
        Auth::forgetGuards();
        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });

    // Laravel's auth.session middleware has nothing to compare either.
    it('goes back when the admin no longer has a password', function () {
        impersonating();
        User::query()->whereKey($this->admin->getKey())->update(['password' => null]);

        stopImpersonating()->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    // A session from before Laravel kept a keyed hash holds the raw one,
    // which its auth.session middleware still takes.
    it('goes back with the raw password hash parked, as laravel\'s auth.session middleware takes it', function () {
        impersonating();
        session()->put(Impersonation::KEY.'.parked.password_hash_web', $this->admin->fresh()->getAuthPassword());

        stopImpersonating()->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('has an inertia visit load the next page in full, starting and stopping', function () {
        config(['keyring.impersonation.return_to' => '/admin/users']);
        adminSignsIn();

        $this->inertia()->post(route('keyring.impersonation.store', $this->user->getKey()))
            ->assertConflict()
            ->assertHeader('X-Inertia-Location', url('/dashboard'))
            ->assertHeader('Clear-Site-Data', '"cache", "storage"')
            ->assertSessionHas('status', 'impersonation-started');

        expect(Keyring::impersonating())->toBeTrue();

        $this->inertia()->delete(route('keyring.impersonation.destroy'))
            ->assertConflict()
            ->assertHeader('X-Inertia-Location', url('/admin/users'))
            ->assertHeader('Clear-Site-Data', '"cache", "storage"')
            ->assertSessionHas('status', 'impersonation-ended');

        expect(Keyring::impersonating())->toBeFalse()
            ->and(Auth::id())->toBe($this->admin->getKey());
    });

    // A cookie session lives in the browser, where nothing can destroy a
    // copy of the one it had while impersonating, with the admin's proofs
    // parked in it.
    it('leaves a copy of a cookie session from while impersonating nothing to go back to', function () {
        onTheCookieDriver();
        $own = impersonating();
        $during = cookiesOf($this->get('/whoami')->assertOk());

        $back = cookiesOf(stopImpersonating()->assertRedirect('/dashboard'));

        expect(session(Sessions::KEY))->not->toBe($own)
            ->and(record($own)->replacedBy)->toBe(session(Sessions::KEY));

        $this->flushSession();
        Auth::forgetGuards();
        $this->withCredentials()->withCookies($during)->getJson('/whoami')->assertUnauthorized();

        $this->flushSession();
        Auth::forgetGuards();
        expect($this->withCredentials()->withCookies($back)->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
    });
});

describe('ending by itself', function () {
    it('goes back to the admin after impersonation.lifetime', function () {
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        $this->travel(61)->minutes();

        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended')->assertHeader('Clear-Site-Data');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('signs out on the next request once the admin\'s password changed', function () {
        $own = impersonating();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        app('router')->pushMiddlewareToGroup('web', LaravelAuthenticateSession::class);
        app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);

        User::query()->whereKey($this->admin->getKey())->update(['password' => Hash::make('changed somewhere else')]);
        Auth::forgetGuards();

        $this->get('/welcome')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
    });

    it('signs out after impersonation.lifetime rather than going back, with laravel\'s auth.session middleware, once the admin\'s password changed', function () {
        app('router')->pushMiddlewareToGroup('web', LaravelAuthenticateSession::class);
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);
        $own = impersonating();
        $this->get('/whoami')->assertOk();

        User::query()->whereKey($this->admin->getKey())->update(['password' => Hash::make('changed somewhere else')]);
        $this->travel(61)->minutes();
        Auth::forgetGuards();

        $this->get('/whoami')->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
        Auth::forgetGuards();
        $this->get('/whoami')->assertRedirect('/login');
    });

    it('tells a json client with a 409', function () {
        impersonating();
        $this->travel(61)->minutes();

        $this->getJson('/whoami')->assertConflict()->assertJson(['status' => 'impersonation-ended', 'redirect' => url('/dashboard')]);
    });

    it('has an inertia visit load the page in full', function () {
        impersonating();
        $this->travel(61)->minutes();

        $this->inertia()->get('/whoami')->assertConflict()->assertHeader('X-Inertia-Location', url('/dashboard'));
    });

    // Both sessions are kept up together, so only an admin's remembered
    // session outlasts the one they're impersonating in.
    it('ends when the impersonated session idles out', function () {
        config(['keyring.sessions.idle' => '30m']);
        adminSignsIn(remember: true);
        impersonate($this->user);

        $this->travel(31)->minutes();

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('ends, back to the admin, when the user ends the session from their own list', function () {
        $own = impersonating();
        $admin = session()->all();
        $this->flushSession();
        Auth::forgetGuards();

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);
        $listed = collect($this->getJson(route('keyring.sessions.index'))->json('sessions'))->firstWhere('impersonated', true);

        expect($listed['impersonator'])->toBe('Ada Admin');

        $this->deleteJson(route('keyring.sessions.destroy', $listed['id']))->assertOk();

        sendBackSession($admin);
        $this->get('/whoami')->assertRedirect('/dashboard');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['ended']);
    });

    it('ends when the user may no longer sign in', function () {
        impersonating();
        Keyring::allowSignInWhen(fn (User $user) => ! $user->is($this->user));

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey());
    });

    it('signs out when the admin\'s own session ends meanwhile, as with signing out everywhere', function () {
        $own = impersonating();

        app(Sessions::class)->signOutEverywhere($this->admin);

        // A page guests may see too: Laravel's auth middleware would turn
        // the browser away first, to the login page, which is one.
        $this->get('/welcome')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull();
    });

    // The impersonated record still says who, and which of their sessions
    // was parked: nobody can go back to it now, so it ends.
    it('signs out when the session no longer says who is impersonating, ending the admin\'s parked session', function () {
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        session()->forget(Impersonation::KEY);

        $this->get('/whoami')->assertRedirect('/login');

        expect(record($own)->revokedAt)->not->toBeNull();
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->impersonator?->is($this->admin) && $event->user->is($this->user)
            && $event->reason === ImpersonationEndReason::Lost && ! $event->returned);
    });

    it('goes back when the impersonated session has no record', function () {
        $own = impersonating();
        session()->forget(Sessions::KEY);

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy);
    });

    it('ends, back to the admin, once they may no longer impersonate the user', function () {
        $own = impersonating();
        Keyring::allowImpersonationWhen(fn () => false);

        $this->get('/whoami')->assertRedirect('/dashboard')->assertSessionHas('status', 'impersonation-ended');

        expect(session(Sessions::KEY))->toBe(record($own)->replacedBy)
            ->and($this->get('/whoami')->getContent())->toBe((string) $this->admin->getKey())
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['ended']);
    });

    it('brings the admin back signed in where sessions end with their level, having kept it from lapsing', function () {
        config(['keyring.sessions.end_on_lapse' => true]);
        impersonating();

        $this->travel(40)->minutes();
        $this->get('/whoami')->assertOk();
        $this->travel(21)->minutes();

        $this->get('/whoami')->assertRedirect('/dashboard');

        expect($this->get('/whoami')->assertOk()->getContent())->toBe((string) $this->admin->getKey());
        $this->get('/billing')->assertOk();
    });

    // Nothing is left for the next sign in on the browser to go back with.
    it('signs out when the user can no longer be loaded', function () {
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        $this->user->delete();
        Auth::forgetGuards();

        // A page guests may see too: Laravel's auth middleware would turn
        // the browser away first, to the login page, which is one.
        $this->get('/welcome')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        expect(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull()
            ->and(logEntry('impersonation_ended'))
            ->authenticatable_id->toBe($this->admin->getKey())
            ->meta->toBe(['impersonator' => (string) $this->admin->getKey(), 'user' => null, 'reason' => 'lost', 'returned' => false, 'role' => 'impersonator']);
        expect($this->get('/welcome')->getContent())->toBe('guest');
    });

    it('signs out, rather than going back, when someone else is signed in on the session', function () {
        $own = impersonating();
        $parked = session(Impersonation::KEY);
        $this->flushSession();
        Auth::forgetGuards();

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);
        session()->put(Impersonation::KEY, $parked);

        $this->get('/whoami')->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['lost']);
    });

    // The app's own Auth::login() on the session, once the impersonated
    // record is gone (pruned, or dropped by the cache), leaves no record to
    // say whose session it is: the guard's user does.
    it('signs out, rather than going back, when someone else is signed in on a session with no record', function () {
        $own = impersonating();
        $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        session()->forget(Sessions::KEY);
        session()->put(Auth::guard('web')->getName(), $other->getKey());
        Auth::forgetGuards();

        $this->get('/whoami')->assertRedirect('/login');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['lost']);
    });

    // As any session that ends there is.
    it('asks for a page that also serves guests again, as a guest, when it signs out', function () {
        config(['keyring.sessions.continue_as_guest' => ['welcome']]);
        Route::middleware('web')->get('/welcome', fn () => Auth::check() ? (string) Auth::id() : 'guest')->name('welcome');
        app('router')->getRoutes()->refreshNameLookups();
        $own = impersonating();

        app(Sessions::class)->signOutEverywhere($this->admin);

        $this->get('/welcome?tab=news')->assertRedirect('/welcome?tab=news')->assertSessionHas('status', 'signed-out')->assertHeader('Clear-Site-Data');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and($this->get('/welcome?tab=news')->getContent())->toBe('guest');
        $this->getJson('/welcome')->assertOk();
    });

    it('signs out for the reason it ended for in the end', function (Closure $meanwhile, string $reason) {
        Keyring::respondWith(SignedOutResponse::class, fn ($app, array $with) => new class($with['reason']) implements SignedOutResponse
        {
            public function __construct(public string $reason) {}

            public function toResponse($request)
            {
                return response("signed out: {$this->reason}", 401);
            }
        });
        $own = impersonating();
        $meanwhile->call($this, $own);

        expect($this->get('/welcome')->assertUnauthorized()->getContent())->toBe("signed out: {$reason}");
    })->with([
        // Ended, but with nobody to go back to.
        'the user and the admin signed out everywhere' => [function (string $own) {
            app(SessionRegistry::class)->revoke(session(Sessions::KEY));
            app(SessionRegistry::class)->revoke($own);
        }, 'impersonator_session_ended'],
        'the user deleted' => [function () {
            $this->user->delete();
            Auth::forgetGuards();
        }, 'lost'],
    ]);

    it('answers a stop with the reason it ended for, too', function () {
        Keyring::respondWith(SignedOutResponse::class, fn ($app, array $with) => new class($with['reason']) implements SignedOutResponse
        {
            public function __construct(public string $reason) {}

            public function toResponse($request)
            {
                return response("signed out: {$this->reason}", 401);
            }
        });
        $own = impersonating();

        // With the middleware out of the way, the stop is the first to see
        // the session is on a record that isn't the impersonation's.
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);
        session()->put(Sessions::KEY, $own);

        expect(stopImpersonating()->assertUnauthorized()->getContent())->toBe('signed out: lost')
            ->and(record($own)->revokedAt)->not->toBeNull();
    });
});

describe('signing out while impersonating', function () {
    it('signs the browser out, ends the admin\'s parked session and leaves the user\'s "remember me" alone', function () {
        $own = impersonating();
        $this->user->forceFill(['remember_token' => 'the users own'])->save();

        $this->post('/logout')->assertRedirect('/');

        expect(Auth::guard('web')->check())->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and($this->user->fresh()->remember_token)->toBe('the users own')
            ->and(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['signed_out']);
    });

    it('does the same for the app\'s own Auth::logout()', function () {
        Route::middleware(['web', 'auth'])->post('/my-logout', function () {
            Auth::logout();

            return 'bye';
        });
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();

        $this->post('/my-logout')->assertOk();

        expect(record($own)->revokedAt)->not->toBeNull();
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->reason === ImpersonationEndReason::SignedOut && ! $event->returned);
    });

    it('does the same when the app empties the session before its Auth::logout()', function () {
        Route::middleware(['web', 'auth'])->post('/my-logout', function (Request $request) {
            $request->session()->invalidate();
            Auth::logout();

            return 'bye';
        });
        Event::fake([ImpersonationEnded::class]);
        $own = impersonating();
        $impersonated = session(Sessions::KEY);

        $this->post('/my-logout')->assertOk();

        expect(record($own)->revokedAt)->not->toBeNull()
            ->and(record($impersonated)->revokedAt)->not->toBeNull();
        Event::assertDispatchedTimes(ImpersonationEnded::class, 1);
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->impersonator->is($this->admin) && $event->user->is($this->user)
            && $event->reason === ImpersonationEndReason::SignedOut);
    });

    // Signing in ends what the session still held, wherever it came from:
    // here it's left behind with the session middleware out of the way.
    it('leaves nothing parked for whoever signs in next on the session', function () {
        $own = impersonating();
        $third = User::create(['name' => 'Third', 'email' => 'third@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        $this->user->delete();
        Auth::forgetGuards();
        app('router')->removeMiddlewareFromGroup('web', AuthenticateSession::class);

        $this->post('/login', ['email' => 'third@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

        app('router')->pushMiddlewareToGroup('web', AuthenticateSession::class);

        expect(session()->has(Impersonation::KEY))->toBeFalse()
            ->and(record($own)->revokedAt)->not->toBeNull()
            ->and($this->get('/whoami')->assertOk()->getContent())->toBe((string) $third->getKey())
            ->and($this->get('/whoami')->getContent())->toBe((string) $third->getKey())
            ->and(logEntry('impersonation_ended')->meta)->toMatchArray(['reason' => 'signed_out', 'user' => null]);
    });
});

describe('the user\'s sessions list', function () {
    it('shows the session with who is in it', function () {
        impersonating();

        $listed = app(Sessions::class)->list(request(), $this->user)->sole();

        expect($listed)->toMatchArray(['impersonated' => true, 'impersonator' => 'Ada Admin', 'remembered' => false, 'device' => null]);
    });

    it('names nobody once the impersonator is gone', function () {
        impersonating();
        $record = record(session(Sessions::KEY));

        $this->admin->delete();

        expect(app(Impersonation::class)->describe($record))->toBeNull()
            ->and(app(Impersonation::class)->describe($record->with(['impersonatorId' => null])))->toBeNull();
    });

    it('leaves it out with impersonation.show_in_sessions off, but can still sign it out everywhere', function () {
        impersonating();
        $impersonated = session(Sessions::KEY);
        config(['keyring.impersonation.show_in_sessions' => false]);
        $this->flushSession();
        Auth::forgetGuards();

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'password']);

        expect($this->getJson(route('keyring.sessions.index'))->json('sessions'))->toHaveCount(1)
            ->and($this->getJson(route('keyring.sessions.index'))->json('sessions.0.impersonated'))->toBeFalse();

        app(Sessions::class)->signOutEverywhere($this->user);

        expect(record($impersonated)->revokedAt)->not->toBeNull();
    });
});

describe('the security log and events', function () {
    it('shows the start and end in both accounts\' activity', function () {
        impersonating();
        stopImpersonating();

        expect(Keyring::activity($this->user)->pluck('type')->all())->toEqualCanonicalizing(['impersonation_started', 'impersonation_ended'])
            ->and(Keyring::activity($this->admin)->pluck('type')->all())->toContain('impersonation_started', 'impersonation_ended')
            ->and(Keyring::unlistedActivityTypes())->toBe([]);
    });

    it('leaves them out of activity with impersonation.show_in_activity off, still logging them', function () {
        config(['keyring.impersonation.show_in_activity' => false, 'keyring.security_log.unlisted' => ['acme.token_issued']]);
        impersonating();
        stopImpersonating();

        expect(Keyring::activity($this->user)->all())->toBe([])
            ->and(Keyring::activity($this->admin)->pluck('type')->all())->not->toContain('impersonation_started', 'impersonation_ended')
            ->and(Keyring::unlistedActivityTypes())->toBe(['acme.token_issued', 'impersonation_started', 'impersonation_ended'])
            ->and(SecurityEvent::query()->whereIn('type', ['impersonation_started', 'impersonation_ended'])->count())->toBe(4);
    });

    // A package could list them without the app knowing, and hide an
    // impersonation from the user it was of.
    it('still shows them when only security_log.unlisted lists them', function () {
        config(['keyring.security_log.unlisted' => ['impersonation_started', 'impersonation_ended']]);
        impersonating();
        stopImpersonating();

        expect(Keyring::activity($this->user)->pluck('type')->all())->toEqualCanonicalizing(['impersonation_started', 'impersonation_ended'])
            ->and(Keyring::unlistedActivityTypes())->toBe([]);
    });

    it('logs the start and end on both accounts', function () {
        impersonating();
        stopImpersonating();

        $entries = SecurityEvent::query()->whereIn('type', ['impersonation_started', 'impersonation_ended'])->oldest('id')->get();
        $both = ['impersonator' => (string) $this->admin->getKey(), 'user' => (string) $this->user->getKey()];

        expect($entries->map(fn (SecurityEvent $entry) => [$entry->type, $entry->authenticatable_id, $entry->meta])->all())->toBe([
            ['impersonation_started', $this->admin->getKey(), [...$both, 'role' => 'impersonator']],
            ['impersonation_started', $this->user->getKey(), [...$both, 'role' => 'impersonated']],
            ['impersonation_ended', $this->admin->getKey(), [...$both, 'reason' => 'stopped', 'returned' => true, 'role' => 'impersonator']],
            ['impersonation_ended', $this->user->getKey(), [...$both, 'reason' => 'stopped', 'returned' => true, 'role' => 'impersonated']],
        ])->and($entries->first()->severity->value)->toBe('notice');
    });

    it('logs the end on the user\'s account alone once the admin is gone', function () {
        impersonating();
        $this->admin->delete();

        stopImpersonating();

        expect(logEntry('impersonation_ended'))
            ->authenticatable_id->toBe($this->user->getKey())
            ->meta->toBe(['impersonator' => null, 'user' => (string) $this->user->getKey(), 'reason' => 'impersonator_session_ended', 'returned' => false, 'role' => 'impersonated']);
    });

    it('logs why it ended', function () {
        impersonating();
        $this->travel(61)->minutes();

        $this->get('/whoami');

        expect(SecurityEvent::query()->where('type', 'impersonation_ended')->get()->pluck('meta.reason')->unique()->all())->toBe(['expired']);
    });

    it('fires events with who and why', function () {
        Event::fake([ImpersonationStarted::class, ImpersonationEnded::class, RegisteredSessionEnded::class]);
        impersonating();
        stopImpersonating();

        Event::assertDispatched(ImpersonationStarted::class, fn (ImpersonationStarted $event) => $event->impersonator->is($this->admin) && $event->user->is($this->user));
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->impersonator->is($this->admin) && $event->user->is($this->user)
            && $event->reason === ImpersonationEndReason::Stopped && $event->returned);
        Event::assertDispatched(RegisteredSessionEnded::class, fn (RegisteredSessionEnded $event) => $event->reason === SessionEndReason::ImpersonationEnded && $event->userId === (string) $this->user->getKey());
    });

    it('names the user who was impersonated, whoever the app has signed in since', function () {
        $other = User::create(['name' => 'Other', 'email' => 'other@example.com', 'password' => 'password', 'email_verified_at' => now()]);
        Route::middleware(['web', 'auth'])->post('/switch', function (Request $request) use ($other) {
            Auth::login($other);

            return Keyring::stopImpersonating($request) === null ? 'signed out' : 'back';
        });
        Event::fake([ImpersonationEnded::class]);
        impersonating();

        expect($this->post('/switch')->getContent())->toBe('signed out')
            ->and(Auth::guard('web')->check())->toBeFalse();
        Event::assertDispatched(ImpersonationEnded::class, fn (ImpersonationEnded $event) => $event->user->is($this->user) && $event->impersonator->is($this->admin)
            && $event->reason === ImpersonationEndReason::Lost && ! $event->returned);
    });
});

describe('the session record', function () {
    it('keeps the impersonator\'s session ID off the server with the rest of its IDs', function () {
        impersonating();

        expect(record(session(Sessions::KEY))->withoutIds()->impersonatorSession)->toBeNull();
    });

    it('needs the migration only for an impersonated session, so signing in works before it', function () {
        Schema::table('keyring_sessions', fn (Blueprint $table) => $table->dropColumn(['impersonator_id', 'impersonator_type', 'impersonator_session']));

        adminSignsIn();

        expect(record(session(Sessions::KEY))->isImpersonated())->toBeFalse();
    });
});
