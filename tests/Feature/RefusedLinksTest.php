<?php

declare(strict_types=1);

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Routing\Exceptions\InvalidSignatureException;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Password as PasswordBroker;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\URL;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Enums\Severity;
use Keyring\Events\LinkRefused;
use Keyring\Events\VerificationRefused;
use Keyring\Facades\Keyring;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Pipeline\Context as PipelineContext;
use Keyring\Pipeline\Steps\CompleteAttempt;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    $this->user = taylor();
});

/**
 * A pending email change with known tokens.
 */
function pendingChange(User $user, array $attributes = []): PendingChange
{
    $change = new PendingChange([
        'attribute' => 'email',
        'value' => 'new@example.com',
        'previous_value' => $user->email,
        'confirm_token' => PendingChange::hashToken('the-confirm-token'),
        'revert_token' => PendingChange::hashToken('the-revert-token'),
        'expires_at' => now()->addDay(),
        ...$attributes,
    ]);

    return tap($change, fn (PendingChange $change) => $change->authenticatable()->associate($user)->save());
}

/**
 * A sign in that reaches the final gate with the rate limit check skipped.
 */
function completeWithoutThrottle(User $user): void
{
    $verification = new Verification('password', null, [Category::Knowledge], at: now()->getTimestamp());
    $attempt = Attempt::start(Purpose::Login, $user, requirement: Requirement::aal1());
    $attempt->record($verification);

    $context = new PipelineContext(Request::create('/login', 'POST'), Purpose::Login, Keyring::factor('password'), $attempt);
    $context->verification = $verification;
    $context->riskLockChecked = true;

    app(CompleteAttempt::class)->handle($context, fn (PipelineContext $context) => $context);
}

it('records a wrong token on an email change link, against the account it was for', function (string $route, string $link) {
    Event::fake([LinkRefused::class]);
    $change = pendingChange($this->user);

    $this->post(route($route, [$change->id, 'a-wrong-token']))->assertSessionHas('status', 'email-change-invalid');

    Event::assertDispatched(fn (LinkRefused $event) => $event->link === $link && $event->reason === 'token' && $event->user->is($this->user));
})->with([
    'confirming' => ['keyring.email.confirm.store', 'email_change_confirm'],
    'undoing' => ['keyring.email.revert.store', 'email_change_revert'],
]);

it('logs the link and the reason, never the token', function () {
    $change = pendingChange($this->user);

    $this->post(route('keyring.email.confirm.store', [$change->id, 'a-wrong-token']));
    $this->post(route('keyring.email.revert.store', [$change->id, 'a-wrong-token']));

    $entries = SecurityEvent::query()->where('type', 'link_refused')->oldest('id')->get();

    expect($entries->pluck('meta')->all())->toEqual([
        ['link' => 'email_change_confirm', 'reason' => 'token'],
        ['link' => 'email_change_revert', 'reason' => 'token'],
    ])
        ->and($entries[0]->user()->is($this->user))->toBeTrue()
        ->and($entries[0]->severity)->toBe(Severity::Warning)
        ->and($entries->toJson())->not->toContain('a-wrong-token')
        ->and($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('records the right token for a change that is over', function (array $attributes, string $route, string $token, string $link) {
    $change = pendingChange($this->user, $attributes);

    $this->post(route($route, [$change->id, $token]))->assertSessionHas('status', 'email-change-invalid');

    expect(logEntry('link_refused')->meta)->toEqual(['link' => $link, 'reason' => 'ended']);
})->with([
    'an expired confirmation' => [['expires_at' => now()->subMinute()], 'keyring.email.confirm.store', 'the-confirm-token', 'email_change_confirm'],
    'a cancelled confirmation' => [['cancelled_at' => now()], 'keyring.email.confirm.store', 'the-confirm-token', 'email_change_confirm'],
    'an undo that was already used' => [['reverted_at' => now()], 'keyring.email.revert.store', 'the-revert-token', 'email_change_revert'],
    'an undo past its time' => [['applied_at' => now()->subDays(8), 'expires_at' => now()->subDays(8), 'revertable_until' => now()->subDay()], 'keyring.email.revert.store', 'the-revert-token', 'email_change_revert'],
]);

it('records a link for a change that does not exist, with the same 404', function (string $route, string $link) {
    $this->post(route($route, ['01jqzzzzzzzzzzzzzzzzzzzzzz', 'any-token']))->assertNotFound();

    expect(logEntry('link_refused'))->meta->toEqual(['link' => $link, 'reason' => 'unknown'])->authenticatable_id->toBeNull();
})->with([
    'confirming' => ['keyring.email.confirm.store', 'email_change_confirm'],
    'undoing' => ['keyring.email.revert.store', 'email_change_revert'],
]);

it('does not record a link that worked', function () {
    $change = pendingChange($this->user);

    $this->post(route('keyring.email.revert.store', [$change->id, 'the-revert-token']))->assertSessionHas('status', 'email-change-reverted');

    expect(loggedTypes())->not->toContain('link_refused');
});

it('records a "this wasn\'t me" link whose signature is wrong or out of date, with the same 403', function () {
    $device = Device::make(['token_hash' => 'theirs']);
    $device->authenticatable()->associate($this->user)->save();

    $forged = $this->post(route('keyring.devices.report.store', $device->id).'?expires=9999999999&signature=forged')->assertForbidden();
    $unsigned = $this->get(route('keyring.devices.report', $device->id))->assertForbidden();
    $expired = URL::temporarySignedRoute('keyring.devices.report.store', now()->subMinute(), ['device' => $device->id], absolute: false);
    $this->post($expired)->assertForbidden();

    expect(SecurityEvent::query()->where('type', 'link_refused')->oldest('id')->pluck('meta')->all())->toEqual([
        ['link' => 'keyring.devices.report.store', 'reason' => 'signature'],
        ['link' => 'keyring.devices.report', 'reason' => 'signature'],
        ['link' => 'keyring.devices.report.store', 'reason' => 'expired'],
    ])
        ->and(SecurityEvent::all()->toJson())->not->toContain('forged')
        ->and($forged->exception)->toBeInstanceOf(InvalidSignatureException::class)
        ->and($unsigned->exception)->toBeInstanceOf(InvalidSignatureException::class)
        ->and($device->fresh()->isRevoked())->toBeFalse();
});

it('lets a signed link that is good through without a word', function () {
    $device = Device::make(['token_hash' => 'theirs']);
    $device->authenticatable()->associate($this->user)->save();

    $this->post(URL::temporarySignedRoute('keyring.devices.report.store', now()->addDay(), ['device' => $device->id], absolute: false))->assertRedirect(route('login'));

    expect($device->fresh()->isRevoked())->toBeTrue()
        ->and(loggedTypes())->toBe(['device_reported']);
});

it('records an email verification link with a wrong signature', function () {
    $user = User::create(['name' => 'New', 'email' => 'new@example.com', 'password' => 'password']);

    $this->actingAs($user)->get(route('verification.verify', [$user->id, sha1($user->email)]).'?expires=9999999999&signature=forged')->assertForbidden();

    expect(logEntry('link_refused')->meta)->toEqual(['link' => 'verification.verify', 'reason' => 'signature'])
        ->and($user->fresh()->hasVerifiedEmail())->toBeFalse();
});

it('records a password reset with a token that is not the one sent, answered as before', function (string $email) {
    Event::fake([LinkRefused::class]);
    PasswordBroker::broker()->createToken($this->user);

    $this->post(route('password.update'), ['token' => 'a-made-up-token', 'email' => $email, 'password' => 'a brand new long passphrase', 'password_confirmation' => 'a brand new long passphrase'])
        ->assertSessionHasErrors(['email' => __('passwords.token')]);

    Event::assertDispatched(fn (LinkRefused $event) => $event->link === 'password_reset' && $event->reason === 'token' && $event->user === null);
})->with(['for an account' => 'taylor@example.com', 'for nobody' => 'nobody@example.com']);

it('logs a refused reset without the token or the address, and not one that only failed validation', function () {
    $this->post(route('password.update'), ['email' => 'taylor@example.com'])->assertSessionHasErrors('token');
    expect(loggedTypes())->toBe([]);

    $this->post(route('password.update'), ['token' => 'a-made-up-token', 'email' => 'taylor@example.com', 'password' => 'a brand new long passphrase', 'password_confirmation' => 'a brand new long passphrase']);

    expect(logEntry('link_refused'))->meta->toEqual(['link' => 'password_reset', 'reason' => 'token'])->authenticatable_id->toBeNull()
        ->and(SecurityEvent::all()->toJson())->not->toContain('a-made-up-token')->not->toContain('taylor@example.com');
});

it('cannot be used to fill the log with refused links', function () {
    config(['keyring.security_log.refusals' => 2]);
    RateLimiter::for('keyring', fn () => Limit::none());
    $change = pendingChange($this->user);

    foreach (range(1, 10) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => "203.0.113.{$attempt}"])->post(route('keyring.email.confirm.store', [$change->id, "guess-{$attempt}"]));
    }

    // Counted against the account the link was for, whatever address asks.
    expect(loggedTypes())->toBe(['link_refused', 'link_refused', 'refusals_limited']);
});

it('records a verification the final gate refused because a step did not run', function () {
    Log::spy();
    Event::fake([VerificationRefused::class]);

    completeWithoutThrottle($this->user);

    Event::assertDispatched(fn (VerificationRefused $event) => $event->attempt->user()->is($this->user)
        && $event->factor === 'password'
        && $event->skipped === [EnsureNotThrottled::class]);

    // The app's log still gets its line.
    Log::shouldHaveReceived('error')->once();
});

it('logs it as critical, against the account', function () {
    completeWithoutThrottle($this->user);

    expect(logEntry('verification_refused'))->factor->toBe('password')->meta->toBe(['skipped' => ['EnsureNotThrottled']])->severity->toBe(Severity::Critical)
        ->and(logEntry('verification_refused')->user()->is($this->user))->toBeTrue();
    $this->assertGuest();
});

it('does not record ordinary validation errors', function () {
    $this->post('/login', ['email' => 'taylor@example.com'])->assertSessionHasErrors('password');
    $this->post('/register', ['email' => 'not-an-address'])->assertSessionHasErrors('email');
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->postJson(route('keyring.email.store'), ['email' => 'not-an-address'])->assertJsonValidationErrors('email');

    expect(loggedTypes())->toBe([]);
});
