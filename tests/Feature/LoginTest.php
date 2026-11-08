<?php

use Illuminate\Support\Facades\Event;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Events\Authenticated;
use Keyring\Events\FactorFailed;
use Keyring\Events\RecoveryCodeUsed;
use Keyring\Facades\Keyring;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Tests\Fixtures\User;

function totpFor(User $user, bool $default = false): Authenticator
{
    return Authenticator::factory()->totp()->for($user, 'authenticatable')->state(['is_default' => $default])->create();
}

it('renders the login page through inertia', function () {
    $this->inertia()->get('/login')
        ->assertOk()
        ->assertJsonPath('component', 'auth/login')
        ->assertJsonPath('props.canRegister', true)
        ->assertJsonPath('props.canResetPassword', true);
});

it('signs in with just a password when nothing else is enrolled', function () {
    Event::fake([Authenticated::class]);
    $user = taylor();

    $this->post('/login', ['email' => 'Taylor@Example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
    Event::assertDispatched(Authenticated::class);
});

it('gives the same error for a wrong password and an unknown account', function () {
    Event::fake([FactorFailed::class]);
    taylor();

    $wrong = $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])
        ->assertSessionHasErrors('email')->getSession()->get('errors')->first('email');

    $unknown = $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'nope'])
        ->assertSessionHasErrors('email')->getSession()->get('errors')->first('email');

    expect($wrong)->toBe($unknown)->toBe(__('auth.failed'));
    $this->assertGuest();
    Event::assertDispatchedTimes(FactorFailed::class, 2);
});

it('asks for a second factor when one is enrolled', function () {
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->assertGuest();

    $this->inertia()->get(route('keyring.login.challenge'))
        ->assertOk()
        ->assertJsonPath('component', 'auth/challenge')
        ->assertJsonPath('props.factor', 'totp')
        ->assertJsonPath('props.authenticator.id', $totp->id);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
});

it('rejects a wrong code and keeps the user signed out', function () {
    $user = taylor();
    totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000'])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.invalid')]);

    $this->assertGuest();
});

it('does not accept the same totp code twice', function () {
    $user = taylor();
    $totp = totpFor($user);
    $code = totpCode($totp->secret);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => $code])->assertRedirect('/dashboard');

    $this->post('/logout');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => $code])->assertSessionHasErrors('code');

    $this->assertGuest();
});

it('offers other ways to sign in', function () {
    $user = taylor();
    $first = totpFor($user, default: true);
    $second = totpFor($user);
    Authenticator::factory()->recoveryCodes()->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $response = $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.authenticator.id', $first->id);

    expect(collect($response->json('props.alternatives'))->pluck('factor')->all())->toBe(['totp', 'recovery'])
        ->and($response->json('props.alternatives.0.id'))->toBe($second->id)
        ->and($response->json('props.alternatives.1.remaining'))->toBe(3);

    $this->inertia()->get(route('keyring.login.challenge', ['recovery']))
        ->assertJsonPath('props.factor', 'recovery');
});

it('signs in with a recovery code once', function () {
    Event::fake([RecoveryCodeUsed::class]);
    $user = taylor();
    totpFor($user);
    Authenticator::factory()->recoveryCodes()->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge', ['recovery']));
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'AAAAA 11111'])->assertRedirect('/dashboard');

    Event::assertDispatched(RecoveryCodeUsed::class, fn ($event) => $event->remaining === 2);

    $this->post('/logout');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge', ['recovery']));
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaaa-11111'])->assertSessionHasErrors('code');
});

it('locks out after too many failures', function () {
    config(['keyring.limits.per_account' => 2]);
    taylor();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertStatus(302)
        ->assertSessionHasErrors('email');

    $this->assertGuest();
});

it('uses the policy to decide what is needed', function () {
    Keyring::require(fn (User $user) => $user->email === 'admin@example.com'
        ? Requirement::aal2()->including(Category::Possession)
        : Requirement::aal1());

    $admin = taylor(['email' => 'admin@example.com']);
    totpFor($admin);

    $this->post('/login', ['email' => 'admin@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $user = taylor(['email' => 'user@example.com']);
    totpFor($user);

    $this->post('/login', ['email' => 'user@example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');
});

it('turns users away when the policy needs factors they do not have', function () {
    Keyring::require(Requirement::aal2());
    taylor();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->get(route('keyring.login.challenge'))
        ->assertRedirect('/login')
        ->assertSessionHasErrors(['email' => __('keyring::keyring.unavailable')]);
});

it('sends people back to login when the attempt has expired', function () {
    $user = taylor();
    totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->travel(11)->minutes();

    $this->get(route('keyring.login.challenge'))->assertRedirect('/login');
});

it('answers json clients with json', function () {
    $user = taylor();
    totpFor($user);

    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertStatus(202)
        ->assertJson(['status' => 'challenge']);
});

it('signs out', function () {
    $user = taylor();

    $this->actingAs($user)->post('/logout')->assertRedirect('/');

    $this->assertGuest();
});
