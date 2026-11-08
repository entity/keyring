<?php

use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Models\Device;
use Keyring\Session\SessionAssurance;
use Keyring\Tests\Fixtures\CreateNewUser;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Notification::fake();
    Keyring::createUsersUsing(CreateNewUser::class);
});

it('renders the register page', function () {
    $this->inertia()->get('/register')->assertJsonPath('component', 'auth/register');
});

it('registers and signs in like any other login', function () {
    $this->post('/register', [
        'name' => 'Taylor',
        'email' => 'Taylor@Example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
    ])->assertRedirect('/dashboard');

    $user = User::sole();

    $this->assertAuthenticatedAs($user);
    expect($user->email)->toBe('taylor@example.com')
        ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
        ->and(Device::count())->toBe(1)
        ->and(app(SessionRegistry::class)->forUser($user))->toHaveCount(1);
});

it('uses the owasp password rules', function () {
    $this->post('/register', [
        'name' => 'Taylor',
        'email' => 'taylor@example.com',
        'password' => 'password',
        'password_confirmation' => 'password',
    ])->assertSessionHasErrors('password');
});

it('verifies email addresses', function () {
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);

    $this->actingAs($user)->inertia()->get('/email/verify')->assertJsonPath('component', 'auth/verify-email');

    $this->post('/email/verification-notification')->assertSessionHas('status', 'verification-link-sent');

    $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)], absolute: false);

    $this->get($url)->assertRedirect('/dashboard?verified=1');
    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
});

it('can turn registration off', function () {
    config(['keyring.features.registration' => false]);

    app('router')->setRoutes(new RouteCollection);
    require __DIR__.'/../../routes/keyring.php';
    app('router')->getRoutes()->refreshNameLookups();

    expect(Route::has('register'))->toBeFalse()
        ->and(Route::has('login'))->toBeTrue();
});
