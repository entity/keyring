<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\LocatesIps;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\Signal;
use Keyring\Events\RiskAssessed;
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Notifications\SecurityNotice;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\Signals\ImpossibleTravel;
use Keyring\Risk\Signals\NewCountry;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\User;

const FIREFOX = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0';

class FakeLocator implements LocatesIps
{
    public ?array $location = null;

    public function locate(Request $request): ?array
    {
        return $this->location;
    }
}

class AlwaysRisky implements Signal
{
    public function __construct(public int $score = 95) {}

    public function assess(Assessment $assessment): ?Finding
    {
        return new Finding('always', $this->score, 'Testing.');
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}

beforeEach(function () {
    Notification::fake();
    $this->locator = new FakeLocator;
    $this->app->instance(LocatesIps::class, $this->locator);

    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/sensitive', fn () => 'sensitive');

    $this->user = taylor();
});

function signInAs(string $agent = FIREFOX, string $password = 'password', array $cookies = []): TestResponse
{
    return test()->withHeader('User-Agent', $agent)->withCookies($cookies)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => $password]);
}

it('asks for another factor when risk is medium', function () {
    Keyring::require(Requirement::aal1());
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->locator->location = ['country' => 'GB'];

    $cookie = signInAs()->assertRedirect('/dashboard')->getCookie('keyring_device')->getValue();
    $this->post('/logout');

    $this->locator->location = ['country' => 'BR'];

    signInAs()->assertRedirect(route('keyring.login.challenge'));
    $this->assertGuest();

    expect(SecurityEvent::where('type', 'risk_step_up')->exists())->toBeTrue();
});

it('does not turn away a password-only user when risk steps up under a policy out of reach', function () {
    Keyring::require(Requirement::aal2()->phishingResistant()->ifEnrolled());
    Keyring::risk([new AlwaysRisky(50)]);

    signInAs()->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('does not ask for more on a familiar device and country', function () {
    Keyring::require(Requirement::aal1());
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->locator->location = ['country' => 'GB'];

    $cookie = signInAs()->getCookie('keyring_device')->getValue();
    $this->post('/logout');

    signInAs(cookies: ['keyring_device' => $cookie])->assertRedirect('/dashboard');
});

/**
 * Sign in and leave that session alive, with a remember token and a trusted
 * device, as if the owner were still using it from another browser.
 */
function liveOwnerSession(): string
{
    Keyring::risk([]);
    signInAs();
    $session = session(Sessions::KEY);

    test()->user->forceFill(['remember_token' => 'owners-token'])->save();
    test()->user->devices()->firstOrFail()->forceFill(['trusted_until' => now()->addDay()])->save();

    test()->flushSession();
    app('auth')->forgetGuards();

    return $session;
}

function expectOwnerStillSignedIn(string $session): void
{
    expect(app(SessionRegistry::class)->find($session)->revokedAt)->toBeNull()
        ->and(test()->user->fresh()->remember_token)->toBe('owners-token')
        ->and(test()->user->devices()->whereNotNull('trusted_until')->exists())->toBeTrue();
}

it('refuses critical risk with the usual error, tells the owner and leaves them signed in', function () {
    Keyring::notify();
    $existing = liveOwnerSession();
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    Event::listen(RiskAssessed::class, function (RiskAssessed $event) use (&$assessed) {
        $assessed = $event;
    });

    Keyring::risk([new AlwaysRisky]);
    signInAs()->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
    expectOwnerStillSignedIn($existing);
    expect($assessed->checkpoint)->toBe(Checkpoint::Login)
        ->and($assessed->action->deny)->toBeTrue()
        ->and($assessed->action->revokeSessions)->toBeFalse()
        ->and(SecurityEvent::where('type', 'risk_denied')->exists())->toBeTrue();
    Notification::assertSentTo($this->user, SecurityNotice::class, fn ($notice) => $notice->type === 'suspicious_activity');
});

it('does not let a custom responder sign the owner out from a login attempt', function () {
    $existing = liveOwnerSession();

    Keyring::risk([new AlwaysRisky])->respond(fn () => Action::deny()->revokeAllSessions()->notify());
    signInAs()->assertSessionHasErrors('email');

    expectOwnerStillSignedIn($existing);
    expect(SecurityEvent::where('type', 'risk_denied')->exists())->toBeTrue();
});

it('still revokes everything when a signed-in session is critical', function () {
    $existing = liveOwnerSession();

    Keyring::risk([new SessionFingerprintChanged(score: 95)]);
    signInAs()->assertRedirect('/dashboard');
    $current = session(Sessions::KEY);

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');

    $this->assertGuest();
    expect(app(SessionRegistry::class)->find($existing)->revokedAt)->not->toBeNull()
        ->and(app(SessionRegistry::class)->find($current)->revokedAt)->not->toBeNull()
        ->and($this->user->fresh()->remember_token)->not->toBe('owners-token')
        ->and($this->user->devices()->whereNotNull('trusted_until')->exists())->toBeFalse();
});

it('can lock sign in for a while', function () {
    Keyring::risk([new AlwaysRisky(40)])->respond(fn ($risk) => $risk->isElevated() ? Action::deny()->lockFor('1h') : Action::allow());

    signInAs()->assertSessionHasErrors('email');

    Keyring::risk([]);
    signInAs()->assertSessionHasErrors('email');

    $this->travel(61)->minutes();
    signInAs()->assertRedirect('/dashboard');
});

it('lifts a risk lock when the password is reset', function () {
    Keyring::risk([new AlwaysRisky(40)])->respond(fn ($risk) => $risk->isElevated() ? Action::deny()->lockFor('1h') : Action::allow());
    signInAs()->assertSessionHasErrors('email');
    Keyring::risk([]);

    $this->post(route('password.update'), [
        'token' => Password::broker()->createToken(User::sole()),
        'email' => User::sole()->email,
        'password' => 'a much longer passphrase',
        'password_confirmation' => 'a much longer passphrase',
    ])->assertRedirect(route('login'));

    $this->post('/login', ['email' => User::sole()->email, 'password' => 'a much longer passphrase'])->assertRedirect('/dashboard');
});

it('spots impossible travel', function () {
    Keyring::risk([NewDevice::class, NewCountry::class, ImpossibleTravel::class]);
    $this->locator->location = ['country' => 'GB', 'latitude' => 51.5, 'longitude' => -0.12];
    signInAs()->assertRedirect('/dashboard');
    $this->post('/logout');

    $this->travel(10)->minutes();
    $this->locator->location = ['country' => 'AU', 'latitude' => -33.87, 'longitude' => 151.21];

    signInAs()->assertSessionHasErrors('email');
    expect(SecurityEvent::where('type', 'risk_denied')->latest('created_at')->first()->meta['reasons'])->toHaveCount(3);
});

it('asks again before sensitive pages when the session moves browser', function () {
    Keyring::risk([SessionFingerprintChanged::class]);
    signInAs();

    $this->withHeader('User-Agent', FIREFOX)->get('/sensitive')->assertOk();

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertOk();
    $this->withHeader('User-Agent', CHROME)->get('/sensitive')->assertRedirect(route('keyring.confirm.challenge'));
});

it('can sign a hijacked session out', function () {
    Keyring::risk([SessionFingerprintChanged::class])->respond(fn ($risk, $at) => $risk->isElevated() ? Action::reauthenticate() : Action::allow());
    signInAs();

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');
    $this->assertGuest();
});

it('locks out for longer each time', function () {
    config(['keyring.limits.per_account' => 2]);

    signInAs(password: 'nope');
    signInAs(password: 'nope');
    signInAs()->assertSessionHasErrors('email');

    $this->travel(61)->seconds();
    signInAs(password: 'nope');
    signInAs(password: 'nope');

    $this->travel(61)->seconds();
    signInAs()->assertSessionHasErrors('email');

    $this->travel(60)->seconds();
    signInAs()->assertRedirect('/dashboard');
});

it('logs security events and shows recent activity', function () {
    signInAs();
    $this->post('/logout');

    $types = Keyring::activity($this->user)->pluck('type');

    expect($types->first())->toBe('signed_out')
        ->and($types->all())->toContain('signed_in', 'new_device');
});

it('asks "was this you?" after someone fails the second factor', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    signInAs();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);

    signInAs();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertSessionHas('keyring.alerts', fn ($alerts) => $alerts[0]['type'] === 'second_factor_failed');

    signInAs();
    expect(session('keyring.alerts'))->toBeNull();
});

it('sends security emails only when asked to', function () {
    signInAs();
    Notification::assertNothingSent();
    $this->post('/logout');

    Keyring::notify(['new_device']);
    $this->user->devices()->delete();
    signInAs();

    Notification::assertSentTo($this->user, SecurityNotice::class, fn ($notice) => $notice->type === 'new_device' && $notice->actionUrl !== null);
});

it('sends security notices through any channel the app chooses', function () {
    Keyring::notify(['new_device'])->securityNoticesUsing(DatabaseSecurityNotice::class);
    $this->user->devices()->delete();

    signInAs();

    Notification::assertSentTo($this->user, DatabaseSecurityNotice::class, function (DatabaseSecurityNotice $notice, array $channels) {
        $data = $notice->toArray($this->user);

        return $channels === ['database']
            && $data['type'] === 'new_device'
            && $data['subject'] === 'New sign-in to your account'
            && $data['action']['text'] === "This wasn't me"
            && array_key_exists('IP address', $data['details']);
    });
});

it('tells the user when someone gets their password but not the second factor', function () {
    Keyring::notify();
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    signInAs();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);

    Notification::assertSentTo($this->user, SecurityNotice::class, fn ($notice) => $notice->type === 'second_factor_failed');
});

class DatabaseSecurityNotice extends SecurityNotice
{
    public function via(object $notifiable): array
    {
        return ['database'];
    }
}
