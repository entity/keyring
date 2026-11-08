<?php

use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Models\Authenticator;
use Keyring\Session\SessionAssurance;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function () {
    Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');

    $this->user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);
});

function signIn(): void
{
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
}

function code(Authenticator $totp, int $step = 0): string
{
    $engine = app(Google2FA::class);

    return $engine->oathTotp($totp->secret, $engine->getTimestamp() + $step);
}

it('lets an aal2 session straight through', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    signIn();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => code($totp)]);

    $this->get('/billing')->assertOk()->assertSee('billing');
});

it('asks a password-only session for a second factor before an aal2 route', function () {
    signIn();
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('component', 'auth/confirm')
        ->assertJsonPath('props.factor', 'totp')
        ->assertJsonPath('props.alternatives', []);

    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => code($totp)])
        ->assertRedirect('/billing');

    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
    $this->get('/billing')->assertOk();
});

it('needs a fresh verification after the window passes', function () {
    signIn();

    $this->get('/account')->assertOk();

    $this->travel(16)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'password');

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'wrong'])
        ->assertSessionHasErrors('password');

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
        ->assertRedirect('/account');

    $this->get('/account')->assertOk();
});

it('does not slide the fresh window with activity', function () {
    signIn();

    $this->travel(10)->minutes();
    $this->get('/account')->assertOk();

    $this->travel(6)->minutes();
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
});

it('lets any enrolled factor confirm, not just the password', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->default()->create();

    signIn();
    $this->post(route('keyring.login.verify', 'totp'), ['code' => code($totp)]);
    $this->travel(16)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'totp');

    // The login code can't be replayed, so use the next one.
    $this->post(route('keyring.confirm.verify', 'totp'), ['code' => code($totp, step: 1)])->assertRedirect('/account');
});

it('also satisfies laravel password confirmation', function () {
    Route::middleware(['web', 'auth', 'password.confirm'])->get('/legacy', fn () => 'legacy');
    signIn();
    $this->travel(4)->hours();

    $this->get(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);

    $this->get('/legacy')->assertOk();
});

it('answers json step-up with a 423', function () {
    signIn();
    $this->travel(16)->minutes();

    $this->getJson('/account')->assertStatus(423)->assertJsonPath('redirect', route('keyring.confirm.challenge'));
});
