<?php

declare(strict_types=1);

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Routing\RouteCollection;
use Illuminate\Routing\UrlGenerator;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\EmailChanges;
use Keyring\Changes\ProtectedAttributes;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Exceptions\MissingAction;
use Keyring\Exceptions\MissingNotification;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\FactorRegistry;
use Keyring\Factors\Password as PasswordFactor;
use Keyring\KeyringManager;
use Keyring\KeyringServiceProvider;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Models\FailureCount;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Notifications\CloneSuspected;
use Keyring\Notifications\ConfirmEmailChange;
use Keyring\Notifications\SecurityNotice;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Outcome;
use Keyring\Pipeline\Steps;
use Keyring\Pipeline\Steps\AssessRisk;
use Keyring\Pipeline\Steps\CompleteAttempt;
use Keyring\Pipeline\Steps\DetermineRequirement;
use Keyring\Pipeline\Steps\EnsureNotRiskLocked;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Pipeline\Steps\ResolveDevice;
use Keyring\Pipeline\Steps\VerifyFactor;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\RegisteredSession;
use Keyring\Support\PasswordRules;

beforeEach(function () {
    $this->user = taylor();
});

it('uses keyring\'s guard for every route, not the app default', function () {
    config(['auth.guards.admin' => ['driver' => 'session', 'provider' => 'users'], 'keyring.guard' => 'admin']);
    Route::setRoutes(new RouteCollection);
    Keyring::routes();

    $this->actingAs($this->user, 'admin')->withAssurance(Assurance::AAL1)
        ->postJson('/user/authenticators/totp')
        ->assertOk();
});

it('lets apps swap the response for every action', function () {
    app()->bind(StatusResponse::class, fn ($app, array $parameters) => new class($parameters['status']) implements StatusResponse
    {
        public function __construct(public string $status) {}

        public function toResponse($request)
        {
            return new JsonResponse(['custom' => $this->status]);
        }
    });

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->deleteJson('/user/devices')
        ->assertExactJson(['custom' => 'sessions-revoked']);
});

it('refuses a response it could not build, when the app swaps it in', function () {
    $unfillable = new class('saved') implements StatusResponse
    {
        public function __construct(public string $slug) {}

        public function toResponse($request)
        {
            return response()->noContent();
        }
    };

    expect(fn () => Keyring::respondWith(StatusResponse::class, $unfillable::class))
        ->toThrow(InvalidArgumentException::class, 'asks for $slug, which Keyring can\'t give it. A [StatusResponse] is built with $status, $data, $redirect.')
        ->and(fn () => Keyring::respondWith(StatusResponse::class, stdClass::class))
        ->toThrow(InvalidArgumentException::class, 'must implement');
});

it('builds a swapped response from what the contract says it passes, and the container', function () {
    $response = new class('saved', app('url')) implements StatusResponse
    {
        public function __construct(public string $status, public UrlGenerator $url, public ?string $redirect = null) {}

        public function toResponse($request)
        {
            return response()->noContent();
        }
    };

    Keyring::respondWith(StatusResponse::class, $response::class);

    expect(Keyring::response(StatusResponse::class, status: 'device-revoked', data: [], redirect: '/login'))
        ->toBeInstanceOf($response::class)
        ->status->toBe('device-revoked')
        ->redirect->toBe('/login');
});

it('answers json callers with the status and its message', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->deleteJson('/user/devices')
        ->assertExactJson(['status' => 'sessions-revoked', 'message' => Keyring::statusMessage('sessions-revoked')]);

    expect(Keyring::statusMessage('sessions-revoked'))->toBe("You've been signed out everywhere else.")
        ->and(Keyring::statusMessage('passwords.sent'))->toBeNull()
        ->and(Keyring::statusMessage(null))->toBeNull();
});

it('answers unknown factors with a 404', function () {
    $this->postJson('/login/sms')->assertNotFound();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->postJson('/user/authenticators/sms')->assertNotFound();
});

it('sends its own notification for every type but a suspected clone, until the app says otherwise', function () {
    $keyring = new KeyringManager(new FactorRegistry, app(ProtectedAttributes::class));

    expect(collect(KeyringManager::NOTIFICATIONS)->reject(fn (string $type) => $keyring->hasNotification($type))->values()->all())->toBe(['clone_suspected'])
        ->and($keyring->notification('clone_suspected', ['when' => 'Monday']))->toBeNull();

    // The app's own class for one, another turned off, and the clone turned on.
    $keyring->notifications(['confirm_email_change' => CustomConfirmEmailChange::class, 'new_device' => null])
        ->notifications(['clone_suspected' => CloneSuspected::class]);

    expect($keyring->notification('confirm_email_change', ['url' => 'https://example.com/confirm', 'expiresAt' => now()->addDay()]))->toBeInstanceOf(CustomConfirmEmailChange::class)
        ->and($keyring->hasNotification('new_device'))->toBeFalse()
        ->and($keyring->notification('clone_suspected', ['when' => 'Monday']))->toBeInstanceOf(CloneSuspected::class)
        // The rest are as they were.
        ->and($keyring->hasNotification('password_changed'))->toBeTrue();
});

it('lets the app write the email of every security notice in one place', function () {
    SecurityNotice::toMailUsing(fn (SecurityNotice $notice, object $notifiable) => new MailMessage()
        ->subject('Acme: '.$notice->subject())
        ->line($notice->intro())
        ->line("For {$notifiable->email}, {$notice->when}."));

    try {
        $mail = Keyring::requiredNotification('password_changed', ['when' => 'Monday'])->toMail($this->user);
        $device = Keyring::requiredNotification('new_device', ['when' => 'Monday', 'url' => 'https://example.com/report']);

        expect($mail->subject)->toBe('Acme: Your password was changed')
            ->and(renderedMail($mail)['text'])->toContain('The password for your account was just changed.')->toContain('For taylor@example.com, Monday.')
            ->and($device->toMail($this->user)->subject)->toBe('Acme: New sign-in to your account')
            ->and($device->action())->toBe('This wasn\'t me');
    } finally {
        SecurityNotice::toMailUsing(null);
    }

    // Keyring's own again.
    expect(Keyring::requiredNotification('password_changed', ['when' => 'Monday'])->toMail($this->user)->subject)->toBe('Your password was changed');
});

it('sends the app\'s own notification for an email a flow needs', function () {
    Notification::fake();
    Keyring::notifications(['confirm_email_change' => CustomConfirmEmailChange::class]);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])
        ->assertOk();

    Notification::assertSentOnDemand(CustomConfirmEmailChange::class);
});

it('says which notification is missing before starting a flow that needs it', function () {
    Keyring::notifications(['email_change_notice' => null]);

    $this->withoutExceptionHandling()->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.email.store'), ['email' => 'new@example.com']);
})->throws(MissingNotification::class, 'No notification is registered for [email_change_notice]');

it('says so when an email code has no notification to go out in', function () {
    Keyring::factors([PasswordFactor::class, EmailCode::asExtraStep()]);
    Keyring::notifications(['verification_code' => null]);

    $this->withoutExceptionHandling()->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'email-code'));
})->throws(MissingNotification::class, 'No notification is registered for [verification_code]');

class CustomConfirmEmailChange extends ConfirmEmailChange
{
    //
}

it('raises laravel\'s own auth events for listeners built for them', function () {
    Event::fake([Failed::class, Lockout::class]);
    config(['keyring.limits.per_account' => 1]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);

    Event::assertDispatched(Failed::class, fn ($event) => $event->credentials === ['email' => 'taylor@example.com']);
    Event::assertDispatched(Lockout::class);
});

it('runs the app\'s own password action, with keyring\'s security work around it', function () {
    Keyring::updateUserPasswordsUsing(SymbolsRequired::class);
    $other = new RegisteredSession('other', (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp());
    app(SessionRegistry::class)->save($other);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->putJson(route('user-password.update'), ['current_password' => 'password', 'password' => 'alongpassphrasewithoutsymbols', 'password_confirmation' => 'alongpassphrasewithoutsymbols'])
        ->assertJsonValidationErrors('password');

    $this->putJson(route('user-password.update'), ['current_password' => 'password', 'password' => 'a long passphrase, with symbols!', 'password_confirmation' => 'a long passphrase, with symbols!'])->assertOk();

    expect(Hash::check('a long passphrase, with symbols!', $this->user->fresh()->password))->toBeTrue()
        ->and(app(SessionRegistry::class)->find('other')->revokedAt)->not->toBeNull();
});

it('asks for the current password itself, whatever the app\'s password action checks', function (array $input) {
    Keyring::updateUserPasswordsUsing(ChecksNothing::class);
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->putJson(route('user-password.update'), [...$input, 'password' => 'a much longer passphrase'])
        ->assertJsonValidationErrors('current_password')
        ->assertJsonMissingValidationErrors('password');

    expect(Hash::check('password', $this->user->fresh()->password))->toBeTrue();

    $this->putJson(route('user-password.update'), ['current_password' => 'password', 'password' => 'a much longer passphrase'])->assertOk();

    expect(Hash::check('a much longer passphrase', $this->user->fresh()->password))->toBeTrue();
})->with([
    'none sent' => [[]],
    'an empty one' => [['current_password' => '']],
    'a wrong one' => [['current_password' => 'not-the-password']],
    'not a string' => [['current_password' => ['password']]],
]);

it('lets a user with no password set one through any action, with the fresh verification alone', function () {
    Keyring::updateUserPasswordsUsing(ChecksNothing::class);
    $this->user->forceFill(['password' => null])->saveQuietly();

    $this->actingAs($this->user->fresh())->withAssurance(Assurance::AAL1)
        ->putJson(route('user-password.update'), ['password' => 'a much longer passphrase'])
        ->assertOk();

    expect(Hash::check('a much longer passphrase', $this->user->fresh()->password))->toBeTrue();
});

it('only lets the app\'s password action change the password', function () {
    Keyring::updateUserPasswordsUsing(FillsEverything::class);

    $this->withoutExceptionHandling()->actingAs($this->user)->withAssurance(Assurance::AAL1);

    expect(fn () => $this->putJson(route('user-password.update'), ['current_password' => 'password', 'password' => 'a much longer passphrase', 'email' => 'attacker@example.com']))
        ->toThrow(ProtectedAttributeException::class);
    expect($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('refuses a password action that saves nothing, before signing anyone out', function () {
    Keyring::updateUserPasswordsUsing(SavesNothing::class);
    $other = new RegisteredSession('other', (string) $this->user->id, RegisteredSession::typeOf($this->user), 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp());
    app(SessionRegistry::class)->save($other);

    $this->withoutExceptionHandling()->actingAs($this->user)->withAssurance(Assurance::AAL1);

    expect(fn () => $this->putJson(route('user-password.update'), ['current_password' => 'password', 'password' => 'a much longer passphrase']))
        ->toThrow(LogicException::class, 'without saving a new password');
    expect(app(SessionRegistry::class)->find('other')->revokedAt)->toBeNull();
});

it('validates whether to sign out other sessions itself', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->putJson(route('user-password.update'), [
            'current_password' => 'password',
            'password' => 'a much longer passphrase',
            'password_confirmation' => 'a much longer passphrase',
            'sign_out_others' => 'garbage',
        ])
        ->assertJsonValidationErrors('sign_out_others');
});

it('says how to register an action the app has not registered', function () {
    // Forget the registration TestCase makes and let Keyring bind it again.
    // A fresh app would swap the container and its database connection
    // mid-test, which hangs on Postgres.
    app()->offsetUnset(ResetsUserPasswords::class);
    new KeyringServiceProvider(app())->register();

    expect(fn () => app(ResetsUserPasswords::class))->toThrow(MissingAction::class, 'Keyring::resetUserPasswordsUsing()');
});

it('uses the app\'s own pending change and security event models', function () {
    Notification::fake();
    Keyring::usePendingChangeModel(AppPendingChange::class)->useSecurityEventModel(AppSecurityEvent::class);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])->assertOk();

    expect(app(EmailChanges::class)->pending($this->user))->toBeInstanceOf(AppPendingChange::class)
        ->and(Keyring::activity($this->user)->first())->toBeInstanceOf(AppSecurityEvent::class);
});

it('counts failures in a row with the app\'s own model', function () {
    Keyring::useFailureCountModel(AppFailureCount::class);
    $counted = null;
    AppFailureCount::created(function (AppFailureCount $count) use (&$counted) {
        $counted = $count;
    });

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('email');

    expect(Keyring::failureCountModel())->toBe(AppFailureCount::class)
        ->and($counted)->toBeInstanceOf(AppFailureCount::class)
        ->and($counted->failures)->toBe(1)
        ->and($counted->owner()?->is($this->user))->toBeTrue();
});

dataset('mandatory steps', [
    EnsureNotThrottled::class,
    VerifyFactor::class,
    EnsureNotRiskLocked::class,
    DetermineRequirement::class,
    CompleteAttempt::class,
]);

it('refuses to remove a mandatory pipeline step', function (string $step) {
    expect(fn () => Keyring::pipeline(fn (Steps $steps) => $steps->remove($step)))
        ->toThrow(InvalidArgumentException::class, "[{$step}] is mandatory");
})->with('mandatory steps');

it('refuses to replace a mandatory pipeline step', function (string $step) {
    expect(fn () => Keyring::pipeline(fn (Steps $steps) => $steps->replace($step, NotesItRan::class)))
        ->toThrow(InvalidArgumentException::class, "[{$step}] is mandatory");
})->with('mandatory steps');

it('does not let a pipeline callback build a list of its own', function () {
    expect(fn () => Keyring::pipeline(fn () => new Steps([CompleteAttempt::class])))->toThrow(Error::class);
});

it('still names a step that is not in the pipeline', function () {
    expect(fn () => Keyring::pipeline(fn (Steps $steps) => $steps->remove(NotesItRan::class)))
        ->toThrow(InvalidArgumentException::class, 'is not in the pipeline');
});

it('lets apps add steps around the mandatory ones and replace the others', function () {
    Log::spy();
    Notification::fake();

    Keyring::pipeline(fn (Steps $steps) => $steps
        ->before(EnsureNotThrottled::class, NotesItRan::class)
        ->after(ResolveDevice::class, AlsoNotesItRan::class)
        ->replace(AssessRisk::class, ReplacesRisk::class));

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    expect(config('test.ran'))->toBe([NotesItRan::class, AlsoNotesItRan::class, ReplacesRisk::class])
        ->and(Keyring::steps())->not->toContain(AssessRisk::class)
        ->and(Keyring::dangerouslyChangedSteps())->toBe([]);

    Log::shouldNotHaveReceived('warning');
});

it('keeps refusing a risk locked user when the risk step is swapped out', function (Closure $customise) {
    Keyring::pipeline($customise);
    app(RiskLocks::class)->lock($this->user, 60);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertSessionHasErrors('email');

    $this->assertGuest();
})->with([
    'replaced' => fn (Steps $steps) => $steps->replace(AssessRisk::class, NotesItRan::class),
    'removed' => fn (Steps $steps) => $steps->remove(AssessRisk::class),
]);

it('lets an app dangerously remove a mandatory step, and logs a warning', function () {
    Log::spy();
    Notification::fake();
    config(['keyring.limits.per_account' => 3, 'keyring.limits.per_ip' => 100]);

    Keyring::pipeline(fn (Steps $steps) => $steps->dangerouslyRemove(EnsureNotThrottled::class));

    foreach (range(1, 5) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => "wrong{$attempt}"]);
    }

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    expect(Keyring::dangerouslyChangedSteps())->toBe([EnsureNotThrottled::class]);

    Log::shouldHaveReceived('warning')->once()->withArgs(fn (string $message) => str_contains($message, EnsureNotThrottled::class));
});

it('lets an app dangerously replace a mandatory step, and logs a warning', function () {
    Log::spy();
    Notification::fake();

    Keyring::pipeline(fn (Steps $steps) => $steps->dangerouslyReplace(EnsureNotThrottled::class, NotesItRan::class));

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    expect(config('test.ran'))->toBe([NotesItRan::class]);

    Log::shouldHaveReceived('warning')->once()->withArgs(fn (string $message) => str_contains($message, EnsureNotThrottled::class));
});

it('refuses to sign in when a check did not run for this request', function (Closure $skip) {
    Log::spy();

    $verification = new Verification('password', null, [Category::Knowledge], at: now()->getTimestamp());
    $attempt = Attempt::start(Purpose::Login, $this->user, requirement: Requirement::aal1());
    $attempt->record($verification);

    $context = new Context(Request::create('/login', 'POST'), Purpose::Login, Keyring::factor('password'), $attempt);
    $context->verification = $verification;
    $context->throttleChecked = true;
    $context->riskLockChecked = true;
    $skip($context);

    app(CompleteAttempt::class)->handle($context, fn (Context $context) => $context);

    expect($context->outcome)->toBe(Outcome::Failed);
    $this->assertGuest();

    Log::shouldHaveReceived('error')->once();
})->with([
    'throttling' => fn (Context $context) => $context->throttleChecked = false,
    'the risk lock' => fn (Context $context) => $context->riskLockChecked = false,
    'verification' => fn (Context $context) => $context->verification = null,
]);

class NotesItRan
{
    public function handle(Context $context, Closure $next): Context
    {
        config()->push('test.ran', static::class);

        return $next($context);
    }
}

class AlsoNotesItRan extends NotesItRan {}

class ReplacesRisk extends NotesItRan {}

class AppPendingChange extends PendingChange {}

class AppSecurityEvent extends SecurityEvent {}

class AppFailureCount extends FailureCount {}

class FillsEverything implements UpdatesUserPasswords
{
    public function update(Authenticatable&Model $user, array $input): void
    {
        $user->forceFill(['password' => Hash::make($input['password']), 'email' => $input['email']])->save();
    }
}

class ChecksNothing implements UpdatesUserPasswords
{
    public function update(Authenticatable&Model $user, array $input): void
    {
        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    }
}

class SavesNothing implements UpdatesUserPasswords
{
    public function update(Authenticatable&Model $user, array $input): void {}
}

class SymbolsRequired implements UpdatesUserPasswords
{
    public function update(Authenticatable&Model $user, array $input): void
    {
        Validator::make($input, ['password' => PasswordRules::for($user, fn (Password $rule) => $rule->symbols())])->validate();

        $user->forceFill(['password' => Hash::make($input['password'])])->save();
    }
}

it('has a notification for every type, that builds from what keyring passes and renders', function (string $type) {
    sendNotifications();

    $notification = Keyring::requiredNotification($type, [
        'when' => 'Monday', 'device' => 'Firefox on Windows', 'ip' => '127.0.0.1',
        'name' => 'YubiKey', 'remaining' => 7, 'reasons' => 'A new country.',
        'url' => 'https://example.com/link', 'expiresAt' => now()->addDay(),
        'code' => '12345678', 'minutes' => 10, 'enrolling' => false,
        'email' => 'n•••@example.com', 'revertUrl' => 'https://example.com/revert', 'confirmUrl' => null,
        'loginUrl' => 'https://example.com/login', 'resetUrl' => 'https://example.com/forgot-password',
    ]);

    expect($notification->via($this->user))->toBe(['mail'])
        ->and(renderedMail($notification->toMail($this->user))['text'])->not->toBeEmpty()->not->toContain(':name')->not->toContain(':remaining')->not->toContain(':reasons');
})->with(KeyringManager::NOTIFICATIONS);

// "Bot Checks" in docs/security.md: a check of the app's own goes before
// the limits, so a request it turns away is nobody's failed attempt.
it('lets a step of the app\'s own turn a request away before it counts against anyone', function () {
    Keyring::pipeline(fn (Steps $steps) => $steps->before(EnsureNotThrottled::class, ChecksForBots::class));

    foreach (range(1, 8) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('captcha');
    }

    expect(loggedTypes())->toBe([]);

    // Past the check, the account has every guess it had.
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'human' => 'yes'])->assertRedirect('/dashboard');

    // A challenge page comes after a right password, so it isn't asked again there.
    $this->post('/logout');
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'human' => 'yes'])->assertRedirect(route('keyring.login.challenge'));
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
});

it('neither counts nor clears failures in a row for a request a later step of the app\'s turns away without an answer', function () {
    config(['keyring.limits.per_account' => 100, 'keyring.limits.per_ip' => 100]);
    Keyring::pipeline(fn (Steps $steps) => $steps->after(EnsureNotThrottled::class, PausesSignIns::class));

    foreach (range(1, 2) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    }

    config(['test.paused' => true]);

    foreach (range(1, 3) as $attempt) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->assertGuest();
    }

    expect(FailureCount::query()->sole()->failures)->toBe(2);

    config(['test.paused' => false]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    expect(FailureCount::query()->exists())->toBeFalse();
});

it('refuses a request a rate limit refused, whatever a step in between made of it', function () {
    Log::spy();

    $verification = new Verification('password', null, [Category::Knowledge], at: now()->getTimestamp());
    $attempt = Attempt::start(Purpose::Login, $this->user, requirement: Requirement::aal1());
    $attempt->record($verification);

    $context = new Context(Request::create('/login', 'POST'), Purpose::Login, Keyring::factor('password'), $attempt);
    $context->verification = $verification;
    $context->throttleChecked = true;
    $context->riskLockChecked = true;
    $context->refuse(60);

    app(CompleteAttempt::class)->handle($context, fn (Context $context) => $context);

    expect($context->outcome)->toBe(Outcome::Failed);
    $this->assertGuest();

    Log::shouldNotHaveReceived('error');
});

/**
 * Turns every sign in away while paused, with no answer of its own, as a
 * maintenance switch of the app's might.
 */
class PausesSignIns
{
    public function handle(Context $context, Closure $next): Context
    {
        return config('test.paused') ? $context : $next($context);
    }
}

class ChecksForBots
{
    public function handle(Context $context, Closure $next): Context
    {
        if ($context->identifying && $context->request->input('human') !== 'yes') {
            throw ValidationException::withMessages(['captcha' => 'Please confirm you are not a robot.']);
        }

        return $next($context);
    }
}

// NIST SP 800-63B-4, Sec. 4.6: a notice says who to contact when the
// recipient says the event wasn't theirs.
describe('a support contact', function () {
    /**
     * Keyring's own notification of a type, as it would build it.
     */
    function ownNotification(string $type): Illuminate\Notifications\Notification
    {
        sendNotifications();

        return Keyring::requiredNotification($type, [
            'when' => 'Monday', 'code' => '12345678', 'minutes' => 10,
            'email' => 'n•••@example.com', 'revertUrl' => 'https://example.com/revert',
        ]);
    }

    it('is in every notice about the account once the app sets one', function (string $type) {
        config(['keyring.support_contact' => 'https://example.com/support?from=email']);

        $mail = renderedMail(ownNotification($type)->toMail($this->user));

        expect($mail['text'])->toContain('contact us')->toContain('https://example.com/support?from=email')
            ->and($mail['html'])->toContain('href="https://example.com/support?from=email"');
    })->with([...array_slice(KeyringManager::NOTIFICATIONS, 0, 12), 'verification_code', 'email_change_notice']);

    it('links an email address as one', function () {
        config(['keyring.support_contact' => 'help@example.com']);

        $mail = renderedMail(ownNotification('password_changed')->toMail($this->user));

        expect($mail['html'])->toContain('href="mailto:help@example.com"')->toContain('>help@example.com</a>')
            ->and($mail['text'])->toContain('contact us: [help@example.com](mailto:help@example.com)');
    });

    it('leaves anything that isn\'t a page or an address as plain text', function () {
        config(['keyring.support_contact' => 'Call 020 7946 0000 [or](https://evil.example) visit reception']);

        $mail = renderedMail(ownNotification('password_changed')->toMail($this->user));

        expect($mail['html'])->toContain('contact us: Call 020 7946 0000 [or](https://evil.example) visit reception')->not->toContain('href="https://evil.example"')
            ->and($mail['text'])->toContain('contact us: Call 020 7946 0000 [or](https://evil.example) visit reception');
    });

    it('is left out until then', function (string $type) {
        $notification = ownNotification($type);

        expect($notification->contact)->toBeNull()
            ->and(renderedMail($notification->toMail($this->user))['text'])->not->toContain('contact us');
    })->with(['password_changed', 'verification_code', 'email_change_notice']);

    it('is handed to a notification of the app\'s own that asks for it, and to no other', function () {
        config(['keyring.support_contact' => 'help@example.com']);
        Keyring::notifications(['password_changed' => WantsTheContact::class, 'new_device' => WantsNothing::class]);

        expect(Keyring::notification('password_changed', ['when' => 'Monday'])->contact)->toBe('help@example.com')
            ->and(Keyring::notification('new_device', ['when' => 'Monday']))->toBeInstanceOf(WantsNothing::class);
    });
});

class WantsTheContact extends Illuminate\Notifications\Notification
{
    public function __construct(public ?string $contact = null) {}
}

class WantsNothing extends Illuminate\Notifications\Notification {}
