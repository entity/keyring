<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Models\Authenticator;
use Keyring\Tests\Fixtures\SingleSignOn;

// Starting a sign in from an app's own route, as a social login's callback does.
beforeEach(function () {
    Keyring::factors([Password::class, Totp::class, SingleSignOn::class]);

    Route::middleware('web')->get('/sso/callback', function (Request $request) {
        try {
            return Keyring::attempt($request, 'sso');
        } catch (ValidationException $e) {
            return to_route('login')->withErrors($e->errors());
        }
    });

    $this->user = taylor();
    SingleSignOn::$vouchedFor = 'taylor@example.com';
});

it('signs in the user the provider vouched for', function () {
    $this->get('/sso/callback')->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('still asks for a second factor the user has', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->get('/sso/callback')->assertRedirect(route('keyring.login.challenge'));
    $this->assertGuest();

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('fails like a wrong password when the provider vouched for no one here', function () {
    SingleSignOn::$vouchedFor = 'stranger@example.com';

    $this->get('/sso/callback')->assertRedirect('/login')->assertSessionHasErrors(['email' => __('auth.failed')]);
    $this->assertGuest();
});

it('counts those failures against the address like any other sign in', function () {
    config(['keyring.limits.per_ip' => 2]);
    SingleSignOn::$vouchedFor = null;

    $this->get('/sso/callback');
    $this->get('/sso/callback');
    $this->get('/sso/callback')->assertSessionHasErrors('email');

    expect(session('errors')->first('email'))->toContain('Too many');
});

it('only starts a sign in with a factor that can', function () {
    Route::middleware('web')->get('/totp/callback', fn (Request $request) => Keyring::attempt($request, 'totp'));

    $this->get('/totp/callback')->assertNotFound();
});

it('drops a half-finished sign in when a new one starts', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $other = taylor(['email' => 'abigail@example.com']);

    $this->get('/sso/callback')->assertRedirect(route('keyring.login.challenge'));

    SingleSignOn::$vouchedFor = 'abigail@example.com';
    $this->get('/sso/callback')->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($other);
});

// The provider's answer only arrives with the request that starts a sign in,
// so a challenge or a step-up has nothing of its own to check.
it('does not offer a factor that can only start a sign in as a way to confirm', function () {
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');

    $this->get('/sso/callback')->assertRedirect('/dashboard');
    $this->travel(16)->minutes();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->inertia()->get(route('keyring.confirm.challenge'))
        ->assertJsonPath('props.factor', 'password')
        ->assertJsonPath('props.alternatives', []);
});

it('refuses to confirm with a factor that can only start a sign in', function () {
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');

    $this->get('/sso/callback')->assertRedirect('/dashboard');
    $this->travel(16)->minutes();
    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

    $this->post(route('keyring.confirm.verify', 'sso'))->assertSessionHasErrors();

    $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
});
