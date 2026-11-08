<?php

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\Rules\Password;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Notifications\ConfirmEmailChange;

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

it('lets apps adjust the password rules', function () {
    Keyring::passwordRulesUsing(fn (Password $rule) => $rule->symbols());

    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
        ->putJson(route('user-password.update'), [
            'current_password' => 'password',
            'password' => 'alongpassphrasewithoutsymbols',
            'password_confirmation' => 'alongpassphrasewithoutsymbols',
        ])
        ->assertJsonValidationErrors('password');
});
