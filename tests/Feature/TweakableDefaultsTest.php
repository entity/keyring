<?php

use App\Notifications\Keyring\VerificationCode;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Contracts\Responses\ConfirmationRequiredResponse;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enrollment\Enrollment;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Http\Controllers\AuthenticatedSessionController;
use Keyring\KeyringManager;
use Keyring\Models\Device;
use Keyring\Models\SecurityEvent;
use Keyring\Pipeline\ConsecutiveLimit;
use Keyring\Sessions\Sessions;
use Keyring\Support\Throttle;
use Keyring\Support\Url;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

function device(User $user, array $attributes = []): Device
{
    return tap(Device::make(['token_hash' => Device::hashToken(Str::random()), 'first_seen_at' => now(), 'last_seen_at' => now(), ...$attributes])->authenticatable()->associate($user))->save();
}

it('sends as many codes as the app allows, as often as it allows', function () {
    config(['keyring.limits.codes' => 1, 'keyring.limits.codes_per' => '1m']);

    Throttle::sending('sms', 1);
    expect(fn () => Throttle::sending('sms', 1))->toThrow(ValidationException::class);

    $this->travel(61)->seconds();
    Throttle::sending('sms', 1);
});

it('gives users as long to finish adding a sign-in method as the app says', function () {
    config(['keyring.enrollments.keep_for' => '1h']);

    expect(Enrollment::make('totp')->expiresAt)->toBe(now()->addHour()->getTimestamp());
});

it('forgets failures in a row after as long as the app says', function () {
    config(['keyring.limits.remember_failures_for' => '1d']);

    expect(ConsecutiveLimit::of(100, 'totp', '1')->decaySeconds)->toBe(86400);
});

it('prunes devices on the app\'s schedule', function () {
    config(['keyring.devices.keep_unseen_for' => '10d']);
    $user = taylor();
    device($user, ['last_seen_at' => now()->subDays(5)]);
    $stale = device($user, ['last_seen_at' => now()->subDays(11)]);

    expect((new Device)->prunable()->pluck('id')->all())->toBe([$stale->id]);
});

it('signs "this wasn\'t me" links for as long as the app says', function () {
    config(['keyring.devices.report_link_for' => '2d']);
    $device = device(taylor());

    parse_str((string) parse_url($device->revokeUrl(), PHP_URL_QUERY), $query);

    expect((int) $query['expires'])->toBe(now()->addDays(2)->getTimestamp());
});

it('starts emailed links wherever the app says', function () {
    Keyring::linkRootUsing(fn () => 'https://tenant.example.com/');

    expect(device(taylor())->revokeUrl())->toStartWith('https://tenant.example.com/devices/');
})->after(fn () => Url::rootUsing(null));

it('keeps the ip address the app wants kept', function () {
    Keyring::recordIpsUsing(fn (Request $request) => null);

    $this->post('/login', ['email' => taylor()->email, 'password' => 'password'])->assertRedirect('/dashboard');

    expect(Device::sole()->ip)->toBeNull()
        ->and(SecurityEvent::query()->whereNotNull('ip')->count())->toBe(0)
        ->and(app(SessionRegistry::class)->find(session(Sessions::KEY))->ip)->toBeNull();
});

it('lets users without a second factor reach the routes the app excepts', function () {
    Route::middleware(['web', 'auth', 'keyring.enrolled'])->group(function () {
        Route::get('/billing', fn () => 'billing')->name('billing');
        Route::get('/help', fn () => 'help')->name('help.index');
    });
    config(['keyring.enrollment_except' => ['help.*']]);

    $this->actingAs(taylor());

    $this->get('/billing')->assertForbidden();
    $this->get('/help')->assertOk();
});

it('answers with the app\'s own responses when a session ends or needs confirming', function () {
    Keyring::respondWith(ConfirmationRequiredResponse::class, fn () => new class implements ConfirmationRequiredResponse
    {
        public function toResponse($request)
        {
            return response('confirm first', 418);
        }
    });
    Keyring::respondWith(SignedOutResponse::class, fn ($app, array $with) => new class($with['reason']) implements SignedOutResponse
    {
        public function __construct(public string $reason) {}

        public function toResponse($request)
        {
            return response("signed out: {$this->reason}", 419);
        }
    });
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'account');
    config(['keyring.sessions.idle' => '10m']);

    $this->post('/login', ['email' => taylor()->email, 'password' => 'password']);
    $this->travel(16)->minutes();
    $this->get('/account')->assertStatus(419)->assertSee('signed out: idle');

    config(['keyring.sessions.idle' => null]);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->travel(16)->minutes();
    $this->get('/account')->assertStatus(418)->assertSee('confirm first');
});

it('sends email codes of the length the app picks, for as long as it picks', function () {
    Notification::fake();
    Keyring::factors([Password::class, EmailCode::asSecondFactor(length: 6, expireAfter: '5m')]);

    $this->actingAs(taylor())->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'email-code'))
        ->assertJsonPath('enrollment.length', 6);

    Notification::assertSentTo(auth()->user(), VerificationCode::class, fn (VerificationCode $code) => strlen($code->code) === 6 && $code->minutes === 5);
});

it('names the issuer an authenticator app shows, when the app gives one', function () {
    Keyring::factors([Password::class, new Totp(app(Google2FA::class), issuer: 'Acme Staff')]);

    $url = $this->actingAs(taylor())->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'totp'))
        ->json('enrollment.url');

    expect($url)->toContain('issuer=Acme%20Staff');
});

it('lets an app replace a controller through the container', function () {
    app()->bind(AuthenticatedSessionController::class, fn ($app) => new class($app->make(KeyringManager::class)) extends AuthenticatedSessionController
    {
        public function create(Request $request): mixed
        {
            return 'our own login page';
        }
    });

    $this->get('/login')->assertOk()->assertSee('our own login page');
});
