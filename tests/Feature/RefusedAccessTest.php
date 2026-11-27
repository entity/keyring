<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use Keyring\Enums\Assurance;
use Keyring\Enums\Severity;
use Keyring\Events\AccessRefused;
use Keyring\Events\AuthenticatorRemovalRefused;
use Keyring\Events\EnrollmentRefused;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\SecurityEvent;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    $this->user = taylor();
    $this->other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
});

it('records a request for someone else\'s authenticator, and answers it like one that does not exist', function (string $method, string $route) {
    Event::fake([AccessRefused::class]);
    $theirs = Authenticator::factory()->totp()->for($this->other, 'authenticatable')->create();

    $missing = $this->json($method, route($route, '01jqzzzzzzzzzzzzzzzzzzzzzz'))->assertNotFound();
    $refused = $this->json($method, route($route, $theirs->id), ['name' => 'Mine now'])->assertNotFound();

    expect(str_replace($theirs->id, '01jqzzzzzzzzzzzzzzzzzzzzzz', $refused->getContent()))->toBe($missing->getContent())
        ->and($theirs->fresh()->name)->not->toBe('Mine now');

    Event::assertDispatched(fn (AccessRefused $event) => $event->user->is($this->user) && $event->resource === 'authenticator' && $event->id === $theirs->id);
})->with([
    'renaming it' => ['PATCH', 'keyring.authenticators.update'],
    'removing it' => ['DELETE', 'keyring.authenticators.destroy'],
]);

it('logs it against the account that asked', function () {
    $theirs = Authenticator::factory()->totp()->for($this->other, 'authenticatable')->create();

    $this->patchJson(route('keyring.authenticators.update', $theirs->id), ['name' => 'Mine now'])->assertNotFound();
    $this->deleteJson(route('keyring.authenticators.destroy', $theirs->id))->assertNotFound();

    $entries = SecurityEvent::query()->where('type', 'access_refused')->oldest('id')->get();

    expect($entries)->toHaveCount(2)
        ->and($entries[0]->user()->is($this->user))->toBeTrue()
        ->and($entries[0])->meta->toEqual(['resource' => 'authenticator', 'id' => $theirs->id])->severity->toBe(Severity::Warning)
        ->and($theirs->fresh())->not->toBeNull();
});

it('records a request to sign out someone else\'s device, with the same 404', function () {
    $theirs = Device::make(['token_hash' => 'theirs']);
    $theirs->authenticatable()->associate($this->other)->save();

    $missing = $this->deleteJson(route('keyring.devices.destroy', '01jqzzzzzzzzzzzzzzzzzzzzzz'))->assertNotFound();
    $refused = $this->deleteJson(route('keyring.devices.destroy', $theirs->id))->assertNotFound();

    expect(str_replace($theirs->id, '01jqzzzzzzzzzzzzzzzzzzzzzz', $refused->getContent()))->toBe($missing->getContent())
        ->and($theirs->fresh()->isRevoked())->toBeFalse()
        ->and(SecurityEvent::query()->where('type', 'access_refused')->oldest('id')->pluck('meta')->all())->toEqual([
            ['resource' => 'device', 'id' => '01jqzzzzzzzzzzzzzzzzzzzzzz'],
            ['resource' => 'device', 'id' => $theirs->id],
        ]);
});

it('names the resource after Keyring\'s model when the app uses its own, and keeps a long ID short', function () {
    Keyring::useAuthenticatorModel(OwnAuthenticator::class);

    $this->patchJson(route('keyring.authenticators.update', str_repeat('x', 300)))->assertNotFound();

    expect(logEntry('access_refused')->meta)->toEqual(['resource' => 'authenticator', 'id' => str_repeat('x', 64)]);
});

it('cannot be used to fill the log, one made-up ID at a time', function () {
    config(['keyring.security_log.refusals' => 3]);

    foreach (range(1, 10) as $attempt) {
        $this->patchJson(route('keyring.authenticators.update', "made-up-{$attempt}"))->assertNotFound();
    }

    expect(loggedTypes())->toBe(['access_refused', 'access_refused', 'access_refused', 'refusals_limited']);

    // Someone else's refusals are counted on their own.
    event(new AccessRefused($this->other, 'authenticator', 'made-up'));

    expect(SecurityEvent::query()->where('type', 'access_refused')->count())->toBe(4);
});

it('records a sign-in method that was not added because its proof was wrong', function () {
    Event::fake([EnrollmentRefused::class]);
    $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->assertOk();

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000'])
        ->assertUnprocessable()
        ->assertExactJson(['message' => __('keyring::keyring.invalid'), 'errors' => ['code' => [__('keyring::keyring.invalid')]]]);

    Event::assertDispatched(fn (EnrollmentRefused $event) => $event->user->is($this->user) && $event->factor === 'totp' && $event->reason === 'invalid');
});

it('logs a refused enrollment, but not a form that was only filled in wrong', function () {
    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->json('enrollment.secret');

    // No code at all is a validation error, not a proof that failed.
    $this->postJson(route('keyring.authenticators.confirm', 'totp'), [])->assertJsonValidationErrors('code');
    expect(loggedTypes())->toBe([]);

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => '000000'])->assertUnprocessable();

    expect(logEntry('enrollment_refused'))->factor->toBe('totp')->meta->toBe(['reason' => 'invalid'])->severity->toBe(Severity::Warning)
        ->and(logEntry('enrollment_refused')->user()->is($this->user))->toBeTrue();

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

    expect(SecurityEvent::query()->where('type', 'enrollment_refused')->count())->toBe(1);
});

it('records a key the factor refused with a message of its own', function () {
    Keyring::factors([Password::class, WebAuthn::passkeys()->requireAttestation()]);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'), ['password' => 'password'])->json('enrollment.options');

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => new VirtualAuthenticator()->register($options)])
        ->assertJsonValidationErrors(['credential' => __('keyring::keyring.key_not_accepted')]);

    expect(logEntry('enrollment_refused'))->factor->toBe('passkey')->meta->toBe(['reason' => 'invalid']);
});

it('records an account that may not add a sign-in method yet, with the same 403', function () {
    // Only signed in at all where registration signs new users in.
    revealTakenAddresses();
    $unverified = User::create(['name' => 'New', 'email' => 'new@example.com', 'password' => 'password']);

    $this->actingAs($unverified)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', 'totp'))
        ->assertForbidden()
        ->assertJsonPath('message', __('keyring::keyring.verify_email_first'));

    expect(logEntry('enrollment_refused'))->factor->toBe('totp')->meta->toBe(['reason' => 'not_allowed'])
        ->and(logEntry('enrollment_refused')->user()->is($unverified))->toBeTrue();
});

it('records a refusal for a factor key too long for the log, cut to fit', function () {
    revealTakenAddresses();
    $unverified = User::create(['name' => 'New', 'email' => 'new@example.com', 'password' => 'password']);

    $this->actingAs($unverified)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.authenticators.store', str_repeat('a', 80)))
        ->assertForbidden();

    expect(logEntry('enrollment_refused')->factor)->toBe(str_repeat('a', 64));
});

it('records a refused attempt to remove the last sign-in method the account needs', function () {
    Event::fake([AuthenticatorRemovalRefused::class]);
    Keyring::require(Requirement::aal2());
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->withAssurance(Assurance::AAL2)->deleteJson(route('keyring.authenticators.destroy', $totp->id))
        ->assertUnprocessable()
        ->assertExactJson(['message' => __('keyring::keyring.last_factor'), 'errors' => ['authenticator' => [__('keyring::keyring.last_factor')]]]);

    Event::assertDispatched(fn (AuthenticatorRemovalRefused $event) => $event->user->is($this->user) && $event->authenticator->is($totp));
});

it('logs it, and still has the sign-in method', function () {
    Keyring::require(Requirement::aal2());
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create(['name' => 'Phone']);

    $this->withAssurance(Assurance::AAL2)->deleteJson(route('keyring.authenticators.destroy', $totp->id))->assertJsonValidationErrors('authenticator');

    expect(logEntry('authenticator_removal_refused'))->factor->toBe('totp')->meta->toBe(['name' => 'Phone', 'reason' => 'last_factor'])->severity->toBe(Severity::Warning)
        ->and($totp->fresh())->not->toBeNull()
        ->and(loggedTypes())->toBe(['authenticator_removal_refused']);
});

it('records an email verification link that was made for another account, with the same 403', function () {
    // Only signed in at all where registration signs new users in.
    revealTakenAddresses();
    $other = User::create(['name' => 'Also new', 'email' => 'also-new@example.com', 'password' => 'password']);
    $user = User::create(['name' => 'New', 'email' => 'new@example.com', 'password' => 'password']);
    $theirs = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $other->id, 'hash' => sha1($other->email)], absolute: false);

    $this->actingAs($user)->get($theirs)->assertForbidden();

    expect(logEntry('access_refused'))->meta->toEqual(['resource' => 'email_verification', 'id' => (string) $other->id])
        ->and(logEntry('access_refused')->user()->is($user))->toBeTrue()
        ->and($other->fresh()->hasVerifiedEmail())->toBeFalse()
        ->and($user->fresh()->hasVerifiedEmail())->toBeFalse();

    // Their own still works, and says nothing.
    postSignedLink(URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)], absolute: false))->assertRedirect();

    expect($user->fresh()->hasVerifiedEmail())->toBeTrue()
        ->and(SecurityEvent::query()->where('type', 'access_refused')->count())->toBe(1);
});

class OwnAuthenticator extends Authenticator {}
