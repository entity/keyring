<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Events\SessionEnded;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\Staff;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');

    $this->user = taylor();
});

function signIn(): void
{
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
}

it('lets an aal2 session straight through', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    signIn();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);

    $this->get('/billing')->assertOk()->assertSee('billing');
});

it('asks a password-only session for a second factor before an aal2 route', function () {
    signIn();
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('component', 'auth/confirm')
        ->assertJsonPath('props.factor', 'totp')
        ->assertJsonPath('props.alternatives', []);

    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect('/billing');

    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
    $this->get('/billing')->assertOk();
});

it('drops a confirmation that started under another guard', function () {
    $staff = staff();
    $totp = Authenticator::factory()->totp()->for($staff, 'authenticatable')->create();
    config([
        'auth.providers.staff' => ['driver' => 'eloquent', 'model' => Staff::class],
        'auth.guards.staff' => ['driver' => 'session', 'provider' => 'staff'],
        'auth.defaults.guard' => 'staff',
        'keyring.guard' => 'staff',
    ]);

    $this->actingAs($staff, 'staff')->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    config(['auth.defaults.guard' => 'web', 'keyring.guard' => 'web']);

    // The staff session's record isn't this user's, and would end the
    // session before the confirmation is looked at. Leave only that.
    session()->forget(Sessions::KEY);

    $this->actingAs($this->user, 'web')
        ->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect(route('keyring.confirm.challenge'))
        ->assertSessionHasErrors(['password' => __('keyring::keyring.expired')]);

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    expect($totp->fresh()->last_used_at)->toBeNull();
});

it('drops a confirmation that another user started in the same session', function () {
    $attempts = app(AttemptStore::class);

    $this->actingAs(taylor(['email' => 'abigail@example.com']));
    $attempts->start(Purpose::Confirm, auth()->user());

    $this->actingAs($this->user);

    expect($attempts->current(Purpose::Confirm))->toBeNull();
});

it('stops counting an authenticator once it is removed, in every session it was used in', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    signIn();
    $this->post(route('keyring.login.verify', 'totp'), ['authenticator' => $totp->id, 'code' => totpCode($totp->secret)]);
    $this->get('/billing')->assertOk();

    $totp->delete();

    $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
});

it('needs a fresh verification after the window passes', function () {
    signIn();

    $this->get('/account')->assertOk();

    $this->travel(16)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'password');

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'wrong'])
        ->assertSessionHasErrors('password');

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
        ->assertRedirect('/account');

    $this->get('/account')->assertOk();
});

it('does not slide the fresh window with activity', function () {
    signIn();

    $this->travel(10)->minutes();
    $this->get('/account')->assertOk();

    $this->travel(6)->minutes();
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
});

it('asks a user with two factors for both once the window has passed', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->default()->create();

    signIn();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);
    $this->travel(16)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'totp');

    // The login code can't be replayed, so use the next one. A user with two
    // factors proves both again, as signing in would ask.
    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret, step: 1)])->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');
});

it('also satisfies laravel password confirmation', function () {
    Route::middleware(['web', 'auth', 'password.confirm'])->get('/legacy', fn () => 'legacy');
    // Long enough for Laravel to want the password again, in a session that's still open.
    config(['keyring.sessions.idle' => null]);
    signIn();
    $this->travel(4)->hours();

    $this->get(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);

    $this->get('/legacy')->assertOk();
});

it('answers json step-up with a 423', function () {
    signIn();
    $this->travel(16)->minutes();

    $this->getJson('/account')->assertStatus(423)->assertJsonPath('redirect', route('keyring.confirm.challenge'));
});

it('refuses an aal2 route when the user has nothing that could reach it', function () {
    signIn();

    // A plain confirm wouldn't raise their level, so it would only loop.
    $this->get('/billing')->assertForbidden();
    $this->getJson('/billing')->assertForbidden()->assertJsonPath('status', 'enroll-first');
});

it('sends a user who has nothing that could reach the level to set something up', function () {
    config(['keyring.enrollment_url' => '/settings/security']);
    signIn();

    $this->get('/billing')->assertRedirect('/settings/security')->assertSessionHas('status', 'enroll-first');
    $this->getJson('/billing')->assertForbidden()->assertJsonPath('redirect', '/settings/security');
});

it('brings json callers back to the page they were on after confirming', function () {
    signIn();
    $this->travel(16)->minutes();

    $this->from('/settings')->getJson('/account')->assertStatus(423);

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
        ->assertRedirect('/settings');
});

it('does not send json callers to another site after confirming', function (string $referer) {
    signIn();
    $this->travel(16)->minutes();

    $this->getJson('/account', ['Referer' => $referer])->assertStatus(423);

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
        ->assertRedirect(config('keyring.home'));
})->with([
    'another site' => 'https://evil.example/phish',
    'a lookalike host' => 'http://localhost.evil.example/phish',
    'userinfo before another host' => 'http://localhost@evil.example/phish',
]);

it('does not send a form post to another site after confirming', function () {
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->post('/account', fn () => 'danger zone');
    signIn();
    $this->travel(16)->minutes();

    $this->withoutMiddleware(PreventRequestForgery::class)
        ->post('/account', [], ['Referer' => 'https://evil.example/phish'])
        ->assertRedirect(route('keyring.confirm.challenge'));

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
        ->assertRedirect(config('keyring.home'));
});

it('lets the password through step-up when the only other factor is a used-up set of recovery codes', function () {
    Authenticator::factory()->recoveryCodes([])->for($this->user, 'authenticatable')->create();
    signIn();
    $this->travel(16)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->inertia()->get(route('keyring.confirm.challenge'))->assertJsonPath('props.factor', 'password');
});

it('finishes a step-up with the last recovery code and the password', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $recovery = Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->for($this->user, 'authenticatable')->create();

    signIn();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);
    $this->travel(16)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])
        ->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))->assertJsonPath('props.factor', 'password');
    $this->flushHeaders();
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');

    $this->get('/account')->assertOk();
    expect(Keyring::factor('recovery')->present($recovery->fresh())['remaining'])->toBe(0);
});

it('does not spend a recovery code on a step-up it could never finish', function () {
    Keyring::factors([Password::class, WebAuthn::passkeys(), RecoveryCodes::class]);
    $this->user->forceFill(['password' => null])->saveQuietly();
    Authenticator::factory()->passkey()->default()->for($this->user, 'authenticatable')->create();
    $recovery = Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->freshAt(now()->subHour());
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'passkey')
        ->assertJsonPath('props.alternatives', []);
    $this->flushHeaders();

    $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertSessionHasErrors('code');

    expect(Keyring::factor('recovery')->present($recovery->fresh())['remaining'])->toBe(1);
});

it('does not spend a recovery code on the confirm that replaces a timed-out one', function () {
    $totp = Authenticator::factory()->totp()->default()->for($this->user, 'authenticatable')->create();
    $recovery = Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->for($this->user, 'authenticatable')->create();

    signIn();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);
    $this->travel(16)->minutes();
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    // The attempt times out while the user hunts for their paper codes.
    $this->travel(11)->minutes();
    $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])
        ->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'totp')
        ->assertJsonCount(1, 'props.alternatives')
        ->assertJsonPath('props.alternatives.0.factor', 'password');
    $this->flushHeaders();

    $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertSessionHasErrors('code');
    expect(Keyring::factor('recovery')->present($recovery->fresh())['remaining'])->toBe(1);

    // The real step-up still takes the code, so the user can finish with it.
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');

    $this->get('/account')->assertOk();
    expect(Keyring::factor('recovery')->present($recovery->fresh())['remaining'])->toBe(0);
});

describe('levels lapsing, as nist sp 800-63b asks', function () {
    beforeEach(function () {
        Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        signIn();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)]);
        $this->get('/billing')->assertOk();
    });

    it('lapses aal2 after an hour idle, without signing out', function () {
        $this->travel(61)->minutes();

        $this->get('/home')->assertOk();
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
    });

    it('asks for every factor again once inactivity lapsed the level', function () {
        $this->travel(61)->minutes();
        $this->get('/billing');
        $this->inertia()->get(route('keyring.confirm.challenge'));

        // TOTP checks the real clock, so use the next code: sign in spent this one.
        // The password from sign in no longer counts, so one factor isn't enough.
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)])
            ->assertRedirect(route('keyring.confirm.challenge'));
        $this->inertia()->get(route('keyring.confirm.challenge'))->assertJsonPath('props.factor', 'password');
    });

    it('does not bring a lapsed level back with one factor confirmed somewhere else', function () {
        $this->travel(61)->minutes();
        $this->get('/home')->assertOk();

        // The plain confirm page only asks for one factor. The TOTP code from
        // sign in is still within its 24 hours, but it was before the lapse.
        $this->inertia()->get(route('keyring.confirm.challenge'));
        $this->flushHeaders();
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));

        // What was proved since the lapse does count, so only TOTP is left.
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)])->assertRedirect('/billing');
        $this->get('/billing')->assertOk();
    });

    it('lapses aal2 after 24 hours however active the session is', function () {
        foreach (range(1, 30) as $request) {
            $this->travel(50)->minutes();
            $this->get('/home')->assertOk();
        }

        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
    });

    it('restores the level and resets its clocks when the user verifies again', function () {
        $this->travel(61)->minutes();
        $this->get('/billing');
        $this->inertia()->get(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)]);
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/billing');

        $this->get('/billing')->assertOk();
        $this->travel(59)->minutes();
        $this->get('/billing')->assertOk();
    });

    it('lapses aal3 to aal2 after 15 minutes idle', function () {
        $this->withAssurance(Assurance::AAL3);
        $this->get('/home');
        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);

        $this->travel(16)->minutes();
        $this->get('/home');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
    });
});

// NIST SP 800-63B-4, Sec. 5.2: when the overall or the inactivity timeout
// passes, the session is terminated.
describe('ending a session with the level it signed in at', function () {
    beforeEach(function () {
        config(['keyring.sessions.end_on_lapse' => true]);
        Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
        Event::fake([SessionEnded::class]);

        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    });

    /**
     * Sign in with the password and the authenticator app: an AAL2 session.
     */
    function signInWithBoth(): void
    {
        signIn();
        test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode(test()->totp->secret)])->assertRedirect('/dashboard');
    }

    it('ends an aal2 session after an hour idle', function () {
        signInWithBoth();
        $session = session(Sessions::KEY);

        $this->travel(59)->minutes();
        $this->get('/home')->assertOk();

        $this->travel(61)->minutes();
        $this->get('/home')->assertRedirect('/login')->assertSessionHas('status', 'signed-out');

        $this->assertGuest();
        expect(app(SessionRegistry::class)->find($session)->revokedAt)->not->toBeNull();
        Event::assertDispatched(SessionEnded::class, fn (SessionEnded $event) => $event->reason === 'idle');
    });

    it('answers a json request for a lapsed session with a 401', function () {
        signInWithBoth();
        $this->travel(61)->minutes();

        $this->getJson('/home')->assertUnauthorized()->assertJsonPath('status', 'signed-out');
    });

    it('ends an aal2 session after 24 hours however active it is', function () {
        signInWithBoth();

        foreach (range(1, 28) as $request) {
            $this->travel(50)->minutes();
            $this->get('/home')->assertOk();
        }

        $this->travel(50)->minutes();
        $this->get('/home')->assertRedirect('/login');

        $this->assertGuest();
        Event::assertDispatched(SessionEnded::class, fn (SessionEnded $event) => $event->reason === 'expired');
    });

    it('starts both limits over when the user proves both factors again', function () {
        signInWithBoth();

        foreach (range(1, 27) as $request) {
            $this->travel(50)->minutes();
            $this->get('/home')->assertOk();
        }

        // Twenty-two and a half hours in.
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret)]);
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');

        foreach (range(1, 20) as $request) {
            $this->travel(50)->minutes();
            $this->get('/home')->assertOk();
        }

        $this->assertAuthenticatedAs($this->user);
    });

    it('leaves a session that signed in with one factor alone, whatever it stepped up to', function () {
        Keyring::require(Requirement::aal1());
        signIn();

        $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertRedirect('/billing');
        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);

        $this->travel(90)->minutes();
        $this->get('/home')->assertOk();

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
        $this->assertAuthenticatedAs($this->user);
    });

    it('doesn\'t end a session because the authenticator it signed in with was removed', function () {
        signInWithBoth();
        $this->totp->delete();

        $this->get('/home')->assertOk();
        $this->assertAuthenticatedAs($this->user);
    });

    it('carries on at a lower level when the option is off', function () {
        config(['keyring.sessions.end_on_lapse' => false]);
        signInWithBoth();

        $this->travel(61)->minutes();
        $this->get('/home')->assertOk();

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
    });
});

it('reports an expired confirmation on the field the confirm page asks for next', function () {
    $this->user->forceFill(['password' => null])->saveQuietly();
    Authenticator::factory()->totp()->default()->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user)
        ->post(route('keyring.confirm.verify', 'totp'), ['code' => '000000'])
        ->assertRedirect(route('keyring.confirm.challenge'))
        ->assertSessionHasErrors(['code' => __('keyring::keyring.expired')]);

    $this->inertia()->get(route('keyring.confirm.challenge'))->assertJsonPath('props.factor', 'totp');
});

it('answers 403 when the enrollment page itself asks for what the user has not set up', function () {
    config(['keyring.enrollment_url' => '/billing']);
    signIn();

    $this->get('/billing')->assertForbidden();
});

it('sends a user with nothing to confirm with to set something up, not round in a loop', function () {
    $this->user->forceFill(['password' => null])->saveQuietly();

    $this->actingAs($this->user)->get(route('keyring.confirm.challenge'))->assertForbidden();

    config(['keyring.enrollment_url' => '/settings/security']);

    $this->get(route('keyring.confirm.challenge'))
        ->assertRedirect('/settings/security')
        ->assertSessionHas('status', 'enroll-first');
});

describe('under a policy that asks more of a browser it hasn\'t seen', function () {
    beforeEach(function () {
        Keyring::require(fn (User $user, Attempt $attempt) => $attempt->isNewDevice() ? Requirement::aal2()->ifEnrolled() : Requirement::aal1());

        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        // Signed in a while ago, from a browser the account now knows.
        signIn();
        $this->device = $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])
            ->assertRedirect('/dashboard')
            ->getCookie('known_device')->getValue();

        $this->travel(16)->minutes();
    });

    it('asks for everything a sign in from this browser would, when the browser is not one the account knows', function () {
        $this->withUnencryptedCookies([]);

        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

        // The code alone isn't enough, as it wouldn't be to sign in from here.
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)]);
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');
        $this->get('/account')->assertOk();
    });

    it('asks for both factors of a browser the account knows too, though the policy would sign it in with one', function () {
        $this->withCookie('known_device', $this->device);

        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

        // What the account can give sets the floor, whatever the policy
        // asks at sign in.
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)])
            ->assertRedirect(route('keyring.confirm.challenge'));
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');
        $this->get('/account')->assertOk();
    });
});

it('still hears a policy that asks more than the strongest the account would otherwise be asked for', function () {
    // A passkey that verified the user is the most this account can give
    // on its own. The policy wants the password with it on a new browser.
    Keyring::require(fn (User $user, Attempt $attempt) => $attempt->isNewDevice() ? Requirement::factors(3) : Requirement::aal1());
    $passkey = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
    Keyring::fake()->pass('passkey');

    $this->actingAs($this->user)->withAssurance(Assurance::None);

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'passkey'))->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/account');
    $this->get('/account')->assertOk();

    // On a browser the account knows, the policy asks for less than the
    // passkey, and the passkey is asked for all the same.
    $device = $this->user->devices()->forceCreate(['token_hash' => hash('sha256', 'known'), 'first_seen_at' => now(), 'last_seen_at' => now()]);
    $this->travel(16)->minutes();
    $this->withCookie('known_device', 'known');

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'passkey'))->assertRedirect('/account');
});

it('gives a trusted device no discount on a fresh verification', function () {
    Keyring::require(fn (User $user, Attempt $attempt) => $attempt->device()?->isTrusted() ? Requirement::aal1() : Requirement::aal2()->ifEnrolled());
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    signIn();
    $device = $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret), 'trust' => true])
        ->assertRedirect('/dashboard')
        ->getCookie('known_device')->getValue();

    $this->travel(16)->minutes();
    $this->withCookie('known_device', $device);

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret, 1)]);

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
});

// NIST SP 800-63B-4, Sec. 4.1.2.1: a new authenticator is bound at the
// highest level the account can authenticate at, whatever signing in asks.
describe('asking for the strongest combination the account can give', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()->requireAttestation(), Totp::class, RecoveryCodes::class]);
        Keyring::fake()->pass('security-key', 'passkey');

        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $this->actingAs($this->user);
    });

    /**
     * Whether the session may add a sign-in method right now.
     */
    function mayAddSignInMethod(): bool
    {
        return test()->postJson(route('keyring.authenticators.store', 'totp'))->status() === 200;
    }

    it('takes the key, not a password and a code, from a user who holds one that can\'t leave its device', function (Closure $key) {
        $key = $key()->for($this->user, 'authenticatable')->create();

        // What signing in asks under the default policy, proved just now.
        $this->verifiedWith($this->totp);
        expect(mayAddSignInMethod())->toBeFalse();

        $this->inertia()->get(route('keyring.confirm.challenge'))
            ->assertJsonPath('props.factor', 'security-key')
            ->assertJsonPath('props.alternatives', []);

        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertSessionHasErrors();
        $this->post(route('keyring.confirm.verify', 'security-key'))->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertSessionHasNoErrors();

        $this->flushHeaders();
        expect(mayAddSignInMethod())->toBeTrue();
    })->with([
        'attested, so the account can reach aal3' => fn () => Authenticator::factory()->securityKey()->attested('2fc0579f-8113-47ea-b116-bb5a8db9202a'),
        'not attested, so only its own word for it' => fn () => Authenticator::factory()->securityKey(),
    ]);

    it('takes a recovery code and the password in a lost key\'s place', function () {
        Authenticator::factory()->securityKey()->attested('2fc0579f-8113-47ea-b116-bb5a8db9202a')->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        $this->verifiedWith($this->totp);
        expect(mayAddSignInMethod())->toBeFalse();

        $this->inertia()->get(route('keyring.confirm.challenge'))->assertJsonPath('props.alternatives.0.factor', 'recovery');
        $this->post(route('keyring.confirm.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertSessionHasNoErrors();

        $this->flushHeaders();
        expect(mayAddSignInMethod())->toBeTrue();
    });

    it('takes no recovery code in the key\'s place where the policy takes none at sign in', function () {
        Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade(except: []));
        Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        $this->verifiedWith($this->totp);
        expect(mayAddSignInMethod())->toBeFalse();

        $this->inertia()->get(route('keyring.confirm.challenge'))
            ->assertJsonPath('props.factor', 'security-key')
            ->assertJsonPath('props.alternatives', []);
    });

    it('asks for both factors where the policy would sign in with one', function () {
        Keyring::require(Requirement::aal1());

        $this->withAssurance(Assurance::AAL1);
        expect(mayAddSignInMethod())->toBeFalse();

        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertRedirect(route('keyring.confirm.challenge'));
        expect(mayAddSignInMethod())->toBeFalse();

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertSessionHasNoErrors();
        expect(mayAddSignInMethod())->toBeTrue();
    });

    it('is content with two factors from an account whose passkey syncs', function () {
        Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

        $this->verifiedWith($this->totp);

        expect(mayAddSignInMethod())->toBeTrue();
    });

    it('still lets an account with only a password add its first sign-in method', function () {
        $this->totp->delete();

        $this->withAssurance(Assurance::AAL1);

        expect(mayAddSignInMethod())->toBeTrue();
    });

    it('still lets a user add the key a policy asks for and they don\'t have yet', function () {
        Keyring::require(Requirement::aal3());

        $this->verifiedWith($this->totp);

        expect($this->postJson(route('keyring.authenticators.store', 'security-key'))->status())->toBe(200);
    });
});

// docs/recipes.md, "An App Whose Every Page Needs AAL2".
describe('an app whose every page needs aal2', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, WebAuthn::passkeys()]);
        Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
        config(['keyring.sessions.end_on_lapse' => true, 'keyring.enrollment_url' => '/settings/security']);

        $this->app['router']->pushMiddlewareToGroup('web', 'keyring.enrolled');
        Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/app', fn () => 'app');
        Route::middleware(['web', 'auth'])->get('/settings/security', fn () => 'security');
    });

    it('lets a new user in to add a second factor, and nowhere else until they have', function () {
        signIn();

        $this->get('/app')->assertRedirect('/settings/security');
        $this->get('/settings/security')->assertOk();

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

        // Adding it proved it, so the session is at AAL2 from here.
        $this->get('/app')->assertOk();

        // It signed in with one factor, so it isn't ended when AAL2 runs
        // out: the app's pages ask for both factors again.
        $this->travel(61)->minutes();
        $this->get('/app')->assertRedirect(route('keyring.confirm.challenge'));
        $this->assertAuthenticatedAs($this->user);
    });

    it('ends a session that signed in with both factors once aal2 runs out', function () {
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        signIn();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);

        $this->get('/app')->assertOk();

        $this->travel(61)->minutes();
        $this->get('/app')->assertRedirect('/login');
        $this->assertGuest();
    });
});
