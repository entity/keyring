<?php

use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Exceptions\EmailVerificationRequired;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Models\Device;
use Keyring\Sessions\SessionAssurance;
use Keyring\Tests\Fixtures\Staff;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Notification::fake();
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

it('adds the verified flag to a home url that has a query of its own', function () {
    config(['keyring.home' => '/dashboard?tab=security']);
    $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);

    $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)], absolute: false);

    $this->actingAs($user)->get($url)->assertRedirect('/dashboard?tab=security&verified=1');
});

it('can turn registration off', function () {
    withFeatures(array_values(array_diff(Features::all(), [Features::registration()])));

    expect(Route::has('register'))->toBeFalse()
        ->and(Route::has('login'))->toBeTrue();
});

it('can leave new users signed out, for everyone or per user', function (bool|Closure $when) {
    Keyring::signInAfterRegistering($when);

    $this->post('/register', [
        'name' => 'Taylor',
        'email' => 'taylor@example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
    ])->assertRedirect(route('login'))->assertSessionHas('status', 'registered');

    $this->assertGuest();
    expect(User::sole()->email)->toBe('taylor@example.com');
})->with([
    'never' => false,
    'not this user' => fn () => fn (User $user) => $user->email === 'someone-else@example.com',
]);

describe('email verification', function () {
    it('refuses to register a MustVerifyEmail user without the verification feature, before saving anything', function () {
        config(['keyring.features' => [Features::registration()]]);

        $this->withoutExceptionHandling();

        expect(fn () => $this->post('/register', [
            'name' => 'Taylor',
            'email' => 'taylor@example.com',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ]))->toThrow(EmailVerificationRequired::class, 'Features::emailVerification()');

        expect(User::count())->toBe(0);
    });

    it('stops someone who registered an address they don\'t own from adding a sign-in method', function () {
        $this->post('/register', [
            'name' => 'Not Taylor',
            'email' => 'taylor@example.com',
            'password' => 'correct horse battery staple',
            'password_confirmation' => 'correct horse battery staple',
        ]);

        // Signed in, but the address is unverified, so no passkey can be planted.
        $this->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.authenticators.store', 'passkey'))
            ->assertForbidden()
            ->assertJsonPath('message', __('keyring::keyring.verify_email_first'));
    });

    it('refuses to let users add sign-in methods with registration on when they can\'t verify an address', function () {
        config([
            'auth.providers.staff' => ['driver' => 'eloquent', 'model' => Staff::class],
            'auth.guards.staff' => ['driver' => 'session', 'provider' => 'staff'],
            'keyring.guard' => 'staff',
        ]);
        // The routes read the guard when they're registered.
        withFeatures(Features::all());

        $this->withoutExceptionHandling()->actingAs(staff(), 'staff')->withAssurance(Assurance::AAL1);

        expect(fn () => $this->postJson(route('keyring.authenticators.store', 'totp')))
            ->toThrow(EmailVerificationRequired::class, 'implement MustVerifyEmail');
    });
});
