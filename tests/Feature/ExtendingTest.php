<?php

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Enums\Assurance;
use Keyring\Exceptions\MissingAction;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Facades\Keyring;
use Keyring\Notifications\ConfirmEmailChange;
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

it('lets apps swap a notification through the container', function () {
    Notification::fake();
    app()->bind(ConfirmEmailChange::class, CustomConfirmEmailChange::class);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->postJson(route('keyring.email.store'), ['email' => 'new@example.com'])
        ->assertOk();

    Notification::assertSentOnDemand(CustomConfirmEmailChange::class);
});

it('refuses security email types it does not know', function () {
    expect(fn () => Keyring::notify(['new_device', 'new_devise']))
        ->toThrow(InvalidArgumentException::class, 'Unknown security email types: new_devise.');
});

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
    $other = new RegisteredSession('other', (string) $this->user->id, 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp());
    app(SessionRegistry::class)->save($other);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->putJson(route('user-password.update'), ['password' => 'alongpassphrasewithoutsymbols', 'password_confirmation' => 'alongpassphrasewithoutsymbols'])
        ->assertJsonValidationErrors('password');

    $this->putJson(route('user-password.update'), ['password' => 'a long passphrase, with symbols!', 'password_confirmation' => 'a long passphrase, with symbols!'])->assertOk();

    expect(Hash::check('a long passphrase, with symbols!', $this->user->fresh()->password))->toBeTrue()
        ->and(app(SessionRegistry::class)->find('other')->revokedAt)->not->toBeNull();
});

it('only lets the app\'s password action change the password', function () {
    Keyring::updateUserPasswordsUsing(FillsEverything::class);

    $this->withoutExceptionHandling()->actingAs($this->user)->withAssurance(Assurance::AAL1);

    expect(fn () => $this->putJson(route('user-password.update'), ['password' => 'a much longer passphrase', 'email' => 'attacker@example.com']))
        ->toThrow(ProtectedAttributeException::class);
    expect($this->user->fresh()->email)->toBe('taylor@example.com');
});

it('refuses a password action that saves nothing, before signing anyone out', function () {
    Keyring::updateUserPasswordsUsing(SavesNothing::class);
    $other = new RegisteredSession('other', (string) $this->user->id, 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp());
    app(SessionRegistry::class)->save($other);

    $this->withoutExceptionHandling()->actingAs($this->user)->withAssurance(Assurance::AAL1);

    expect(fn () => $this->putJson(route('user-password.update'), ['password' => 'a much longer passphrase']))
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
    // A fresh app, without the registrations TestCase makes.
    $this->refreshApplication();

    expect(fn () => app(ResetsUserPasswords::class))->toThrow(MissingAction::class, 'Keyring::resetUserPasswordsUsing()');
});

class FillsEverything implements UpdatesUserPasswords
{
    public function update(Authenticatable&Model $user, array $input): void
    {
        $user->forceFill(['password' => Hash::make($input['password']), 'email' => $input['email']])->save();
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
