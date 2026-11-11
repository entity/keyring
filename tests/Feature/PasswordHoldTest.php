<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Keyring\Changes\PasswordHolds;
use Keyring\Enums\Assurance;
use Keyring\Events\PasswordChangeRequired;
use Keyring\Events\RiskAssessed;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\PasswordHold;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\Risk;
use Keyring\Risk\Signals\Signal;

// NIST SP 800-63B-4, Sec. 3.1.1.2: no periodic changes, and a forced one
// when there's evidence the password was compromised.

/**
 * Finds the password everyone signs in with here in a breach.
 */
class PasswordSeenInBreach extends Signal
{
    public function assess(Assessment $assessment): ?Finding
    {
        return new Finding('breached_password', 40, 'The password appears in a known data breach.');
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Login];
    }
}

beforeEach(function () {
    Route::middleware(['web', 'auth'])->group(function () {
        Route::get('/home', fn () => 'home');
        Route::get('/settings/password', fn () => 'choose a new password');
        Route::post('/settings/password', fn () => 'saved');
    });

    config(['keyring.password_change_url' => '/settings/password']);

    $this->user = taylor();
});

function signInWithPassword(string $password = 'password'): void
{
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => $password])->assertRedirect('/dashboard');
}

function chooseNewPassword(string $current = 'password', string $new = 'a much longer passphrase'): void
{
    test()->putJson(route('user-password.update'), [
        'current_password' => $current,
        'password' => $new,
        'password_confirmation' => $new,
    ])->assertOk();
}

it('holds a user on the change-password page until they choose a new password', function () {
    Event::fake([PasswordChangeRequired::class]);
    signInWithPassword();
    $this->get('/home')->assertOk();

    expect(Keyring::requirePasswordChange($this->user, 'Found in the March breach.'))->toBeTrue()
        ->and(Keyring::requiresPasswordChange($this->user))->toBeTrue()
        ->and(app(PasswordHolds::class)->reason($this->user))->toBe('Found in the March breach.');
    Event::assertDispatched(PasswordChangeRequired::class, fn (PasswordChangeRequired $event) => $event->user->is($this->user) && $event->reason === 'Found in the March breach.');

    // Placed from here, so this session hears of it straight away.
    $this->get('/home')->assertRedirect('/settings/password')->assertSessionHas('status', 'change-password');
    $this->getJson('/home')->assertForbidden()->assertJson(['status' => 'change-password', 'redirect' => '/settings/password']);

    // The page itself, the confirmation changing a password takes, and
    // signing out stay open. Nothing else does.
    $this->get('/settings/password')->assertOk()->assertSee('choose a new password');
    $this->post('/settings/password')->assertOk();
    $this->inertia()->get(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('component', 'auth/confirm');
    $this->flushHeaders();
    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertForbidden();

    chooseNewPassword();

    expect(Keyring::requiresPasswordChange($this->user))->toBeFalse()
        ->and(PasswordHold::query()->exists())->toBeFalse();
    $this->get('/home')->assertOk();
});

it('holds one hold per user however often evidence turns up', function () {
    Event::fake([PasswordChangeRequired::class]);

    Keyring::requirePasswordChange($this->user);
    Keyring::requirePasswordChange($this->user, 'Again.');

    expect(PasswordHold::query()->count())->toBe(1);
    Event::assertDispatchedTimes(PasswordChangeRequired::class, 1);
});

it('still holds them after signing out and in again', function () {
    Keyring::requirePasswordChange($this->user);

    signInWithPassword();
    $this->get('/home')->assertRedirect('/settings/password');

    $this->post('/logout');
    $this->flushSession();

    signInWithPassword();
    $this->get('/home')->assertRedirect('/settings/password');
});

it('reaches a session that was already signed in within a minute', function () {
    signInWithPassword();
    $this->get('/home')->assertOk();

    // From somewhere else: a support tool, a job that read a breach list.
    PasswordHold::query()->forceCreate(['authenticatable_type' => $this->user->getMorphClass(), 'authenticatable_id' => $this->user->id]);

    $this->travel(61)->seconds();
    $this->get('/home')->assertRedirect('/settings/password');
});

it('lets them go once the password is reset by email', function () {
    Keyring::requirePasswordChange($this->user);

    $this->post(route('password.update'), [
        'token' => Password::broker()->createToken($this->user),
        'email' => 'taylor@example.com',
        'password' => 'a much longer passphrase',
        'password_confirmation' => 'a much longer passphrase',
    ])->assertSessionHasNoErrors();

    expect(Keyring::requiresPasswordChange($this->user))->toBeFalse();

    signInWithPassword('a much longer passphrase');
    $this->get('/home')->assertOk();
});

it('can be called off without a new password', function () {
    Keyring::requirePasswordChange($this->user);
    Keyring::cancelPasswordChange($this->user);

    signInWithPassword();
    $this->get('/home')->assertOk();
});

it('never holds an account that has no password to change', function () {
    $this->user->forceFill(['password' => null])->saveQuietly();
    Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    expect(Keyring::requirePasswordChange($this->user))->toBeFalse()
        ->and(PasswordHold::query()->exists())->toBeFalse();

    // Nor one whose password was taken away after it was held.
    PasswordHold::query()->forceCreate(['authenticatable_type' => $this->user->getMorphClass(), 'authenticatable_id' => $this->user->id]);

    expect(Keyring::requiresPasswordChange($this->user))->toBeFalse();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2)->get('/home')->assertOk();
});

it('answers 403 when the app has no page to send them to', function () {
    config(['keyring.password_change_url' => null]);
    Keyring::requirePasswordChange($this->user);
    signInWithPassword();

    $this->get('/home')->assertForbidden();
    $this->getJson('/home')->assertForbidden()->assertJsonPath('status', 'change-password');

    chooseNewPassword();
    $this->get('/home')->assertOk();
});

it('leaves guests and everyone else alone', function () {
    Keyring::requirePasswordChange($this->user);
    $other = taylor(['email' => 'abigail@example.com']);

    $this->get('/home')->assertRedirect('/login');
    $this->actingAs($other)->get('/home')->assertOk();
});

it('goes with the user when they are deleted', function () {
    Keyring::requirePasswordChange($this->user);

    $this->user->delete();

    expect(PasswordHold::query()->exists())->toBeFalse();
});

describe('as a risk response', function () {
    beforeEach(function () {
        Keyring::risk()->signals([PasswordSeenInBreach::class]);
    });

    it('lets the sign in through and holds the user for a new password', function () {
        Event::fake([RiskAssessed::class]);
        Keyring::risk()->respond(fn () => Action::allow()->requirePasswordChange());

        signInWithPassword();

        expect(app(PasswordHolds::class)->reason($this->user))->toBe('breached_password');
        Event::assertDispatched(RiskAssessed::class, fn (RiskAssessed $event) => $event->action->name() === 'password_change');

        $this->get('/home')->assertRedirect('/settings/password');

        chooseNewPassword();
        $this->get('/home')->assertOk();
    });

    it('holds the owner even when the sign in that showed the evidence was refused', function () {
        Keyring::risk()->respond(fn (Risk $risk) => $risk->isElevated() ? Action::deny()->requirePasswordChange() : Action::allow());

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertSessionHasErrors('email');
        $this->assertGuest();

        expect(Keyring::requiresPasswordChange($this->user))->toBeTrue();

        Keyring::risk()->signals([]);
        signInWithPassword();
        $this->get('/home')->assertRedirect('/settings/password');
    });

    it('does nothing to an account that signed in without a password', function () {
        Keyring::risk()->respond(fn () => Action::allow()->requirePasswordChange());
        $this->user->forceFill(['password' => null])->saveQuietly();
        Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
        Keyring::fake()->pass('passkey');

        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => ['id' => $this->user->keyring->of('passkey')->sole()->credential_id]]);

        expect(PasswordHold::query()->exists())->toBeFalse();
    });

    it('says what it does', function () {
        expect(Action::allow()->requirePasswordChange())
            ->changePassword->toBeTrue()
            ->doesSomething()->toBeTrue()
            ->name()->toBe('password_change')
            ->and(Action::deny()->requirePasswordChange()->name())->toBe('denied')
            ->and(Action::allow()->changePassword)->toBeFalse();
    });
});
