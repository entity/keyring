<?php

declare(strict_types=1);

use Illuminate\Contracts\Validation\UncompromisedVerifier;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Keyring\Changes\PasswordHolds;
use Keyring\Enums\Assurance;
use Keyring\Enums\Severity;
use Keyring\Events\PasswordChanged;
use Keyring\Events\PasswordChangeRequired;
use Keyring\Events\RiskAssessed;
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\PasswordHold;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\Risk;
use Keyring\Risk\Signals\BreachedPassword;
use Keyring\Risk\Signals\Signal;
use Keyring\Testing\VirtualAuthenticator;

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

// A new hash of the same password is a different string, so the hash
// changing says nothing about the password.
it('keeps the hold when the password they were held for is saved again as the new one', function () {
    Event::fake([PasswordChanged::class]);
    $this->user->forceFill(['password' => Hash::make('a much longer passphrase 1')])->saveQuietly();
    Keyring::requirePasswordChange($this->user);
    signInWithPassword('a much longer passphrase 1');

    $this->putJson(route('user-password.update'), [
        'current_password' => 'a much longer passphrase 1',
        'password' => 'a much longer passphrase 1',
        'password_confirmation' => 'a much longer passphrase 1',
    ])->assertUnprocessable()->assertJsonValidationErrors(['password' => __('keyring::keyring.password_unchanged')]);

    expect(Keyring::requiresPasswordChange($this->user))->toBeTrue();
    Event::assertNotDispatched(PasswordChanged::class);
    $this->get('/home')->assertRedirect('/settings/password');

    chooseNewPassword('a much longer passphrase 1', 'another passphrase altogether');

    expect(Keyring::requiresPasswordChange($this->user))->toBeFalse();
    Event::assertDispatchedTimes(PasswordChanged::class, 1);
});

it('keeps the hold through a reset to the same password, without telling the link\'s holder it was the same', function () {
    $this->user->forceFill(['password' => Hash::make('a much longer passphrase 1')])->saveQuietly();
    Keyring::requirePasswordChange($this->user);

    $reset = fn (string $password) => $this->post(route('password.update'), [
        'token' => Password::broker()->createToken($this->user),
        'email' => 'taylor@example.com',
        'password' => $password,
        'password_confirmation' => $password,
    ]);

    // Answered like any reset: whoever holds the link learns nothing of the
    // password it replaced.
    $reset('a much longer passphrase 1')->assertSessionHasNoErrors()->assertRedirect(route('login'));

    expect(Keyring::requiresPasswordChange($this->user))->toBeTrue();

    $this->travel(2)->minutes();
    $reset('another passphrase altogether')->assertSessionHasNoErrors();

    expect(Keyring::requiresPasswordChange($this->user))->toBeFalse();
});

// Nothing to be the same as: the field is only checked for an account that
// has a password, so what it holds proves nothing for one that hasn't.
it('sets a first password for an account that had none, whatever the current password field holds', function () {
    Event::fake([PasswordChanged::class]);
    $this->user->forceFill(['password' => null])->saveQuietly();
    Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user->fresh())->withAssurance(Assurance::AAL2)->putJson(route('user-password.update'), [
        'current_password' => 'a much longer passphrase 1',
        'password' => 'a much longer passphrase 1',
        'password_confirmation' => 'a much longer passphrase 1',
    ])->assertOk();

    expect(Hash::check('a much longer passphrase 1', $this->user->fresh()->password))->toBeTrue();
    Event::assertDispatchedTimes(PasswordChanged::class, 1);
});

// The hasher throws for a stored value it won't check, and by then the new
// password is saved: the reset has to finish, sessions, link and all.
it('finishes a reset for an account whose stored password is not a hash the app checks', function (string $stored) {
    config(['hashing.bcrypt.verify' => true]);
    DB::table('users')->where('id', $this->user->id)->update(['password' => $stored]);
    Keyring::requirePasswordChange($this->user->fresh());
    $token = Password::broker()->createToken($this->user);

    $this->post(route('password.update'), [
        'token' => $token,
        'email' => 'taylor@example.com',
        'password' => 'a much longer passphrase',
        'password_confirmation' => 'a much longer passphrase',
    ])->assertSessionHasNoErrors()->assertRedirect(route('login'));

    expect(Hash::check('a much longer passphrase', $this->user->fresh()->password))->toBeTrue()
        ->and(Password::broker()->tokenExists($this->user->fresh(), $token))->toBeFalse()
        ->and(Keyring::requiresPasswordChange($this->user))->toBeFalse();
})->with([
    'an imported md5' => [md5('password')],
    'another algorithm\'s hash' => [password_hash('password', PASSWORD_ARGON2ID)],
    'a placeholder' => ['!'],
]);

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
        $key = new VirtualAuthenticator;
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');
        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();
        $this->post('/logout');

        Keyring::risk()->respond(fn () => Action::allow()->requirePasswordChange());
        $this->user->forceFill(['password' => null])->saveQuietly();

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->assertOk()->json('options');
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
            ->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        expect(PasswordHold::query()->exists())->toBeFalse();
        $this->get('/home')->assertOk();
    });

    describe('by default, when the password just used is found in a breach', function () {
        beforeEach(function () {
            // Have I Been Pwned knows every password.
            $this->app->instance(UncompromisedVerifier::class, new class implements UncompromisedVerifier
            {
                public function verify($data): bool
                {
                    return false;
                }
            });

            Keyring::risk()->signals([BreachedPassword::class]);
        });

        it('holds the user until they choose another, and logs that it did', function () {
            signInWithPassword();

            expect(app(PasswordHolds::class)->reason($this->user))->toBe('breached_password')
                ->and(logEntry('risk_password_change'))
                ->severity->toBe(Severity::Notice)
                ->meta->toMatchArray(['checkpoint' => 'login', 'reasons' => ['The password appears in a known data breach.']]);

            $this->get('/home')->assertRedirect('/settings/password');

            chooseNewPassword();
            $this->get('/home')->assertOk();
        });

        it('does so whatever the finding scores', function () {
            Keyring::risk()->signals([app()->make(BreachedPassword::class, ['score' => 1])]);

            signInWithPassword();

            expect(Keyring::requiresPasswordChange($this->user))->toBeTrue();
        });

        it('still asks for the second factor the level calls for', function () {
            $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
            Keyring::require(Requirement::aal1());

            $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
            $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');

            $this->get('/home')->assertRedirect('/settings/password');
        });

        it('looks at no password sent along with a sign in that didn\'t use one', function () {
            $key = new VirtualAuthenticator;
            $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
            $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');
            $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();
            $this->post('/logout');

            $options = $this->getJson(route('keyring.login.options', 'passkey'))->assertOk()->json('options');
            $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options), 'password' => 'password'])
                ->assertRedirect('/dashboard');

            $this->assertAuthenticatedAs($this->user);
            expect(Keyring::requiresPasswordChange($this->user))->toBeFalse();
        });

        it('leaves the answer to a responder of the app\'s own', function () {
            Keyring::risk()->respond(fn (Risk $risk) => $risk->isElevated() ? Action::stepUp() : Action::allow());

            signInWithPassword();

            expect(Keyring::requiresPasswordChange($this->user))->toBeFalse();
        });
    });

    it('holds nobody by default for a finding that isn\'t about the password', function () {
        Keyring::risk()->signals([new class extends Signal
        {
            public function assess(Assessment $assessment): Finding
            {
                return new Finding('new_country', 40, 'Signing in from a new country (FR).');
            }
        }]);

        signInWithPassword();

        expect(Keyring::requiresPasswordChange($this->user))->toBeFalse();
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
