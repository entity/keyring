<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password as PasswordBroker;
use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Support\Input;
use Keyring\Tests\Fixtures\SmsCode;
use Keyring\Tests\Fixtures\User;

// A URL is kept where a body isn't: access logs, proxies, the browser's
// history. So what proves something is only read from the body, and a proof
// in the query string of a POST is one that wasn't sent.
beforeEach(function () {
    $this->user = taylor();
});

it('takes no password from the query string of a sign in', function () {
    $this->post('/login?password=password', ['email' => 'taylor@example.com'])->assertSessionHasErrors('password');
    $this->post('/login?email=taylor@example.com&password=password')->assertSessionHasErrors(['email', 'password']);
    $this->postJson('/login?password=password', ['email' => 'taylor@example.com'])->assertJsonValidationErrors('password');

    $this->assertGuest();
});

it('still signs in from a form, whatever the query string holds', function () {
    $this->post('/login?password=wrong&email=nobody@example.com', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('still signs in from JSON, whatever the query string holds', function () {
    $this->postJson('/login?password=wrong&email=nobody@example.com', ['email' => 'taylor@example.com', 'password' => 'password'])->assertOk();

    $this->assertAuthenticatedAs($this->user);
});

it('takes no code from the query string of a challenge', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

    $this->post(route('keyring.login.verify', 'totp').'?code='.totpCode($totp->secret))->assertSessionHasErrors('code');
    $this->assertGuest();

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
});

it('takes no password from the query string of a step-up', function () {
    Route::middleware(['web', 'auth', 'keyring.fresh:5m'])->get('/billing', fn () => 'billing');

    $this->actingAs($this->user)->freshAt(now()->subHour())->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));

    $this->post(route('keyring.confirm.verify', 'password').'?password=password')->assertSessionHasErrors('password');
    $this->get('/billing')->assertRedirect(route('keyring.confirm.challenge'));

    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])->assertRedirect('/billing');
});

it('takes no code from the query string when confirming a new sign-in method', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');

    $this->postJson(route('keyring.authenticators.confirm', 'totp').'?code='.totpCode($secret))->assertJsonValidationErrors('code');
    expect(Authenticator::count())->toBe(0);

    $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();
    expect(Authenticator::query()->where('factor', 'totp')->count())->toBe(1);
});

it('takes no token or password from the query string of a reset', function () {
    $token = PasswordBroker::broker()->createToken($this->user);

    $this->post(route('password.update').'?'.http_build_query(['token' => $token, 'password' => 'a-long-new-password', 'password_confirmation' => 'a-long-new-password']), ['email' => 'taylor@example.com'])
        ->assertSessionHasErrors(['token', 'password']);

    // The action's own rules only see the body too.
    $this->post(route('password.update').'?password_confirmation=a-long-new-password', ['token' => $token, 'email' => 'taylor@example.com', 'password' => 'a-long-new-password'])
        ->assertSessionHasErrors('password');

    expect(Hash::check('password', $this->user->fresh()->password))->toBeTrue();
});

it('takes no password from the query string of a password change', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $new = ['password' => 'a-long-new-password', 'password_confirmation' => 'a-long-new-password'];

    $this->put(route('user-password.update').'?'.http_build_query(['current_password' => 'password']), $new)->assertSessionHasErrors('current_password');

    // The action's own rules only see the body too.
    $this->put(route('user-password.update').'?'.http_build_query($new), ['current_password' => 'password'])->assertSessionHasErrors('password');

    expect(Hash::check('password', $this->user->fresh()->password))->toBeTrue();
});

it('takes no password from the query string of a registration', function () {
    $this->post('/register?'.http_build_query(['password' => 'a-long-new-password', 'password_confirmation' => 'a-long-new-password']), ['name' => 'Abigail', 'email' => 'abigail@example.com'])
        ->assertSessionHasErrors('password');

    expect(User::query()->where('email', 'abigail@example.com')->exists())->toBeFalse();
});

it('takes no password from the query string when removing the last second factor', function () {
    $user = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'a password long enough alone', 'email_verified_at' => now()]);
    $totp = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
    $this->actingAs($user)->withAssurance(Assurance::AAL2);

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id).'?password=a+password+long+enough+alone')
        ->assertJsonValidationErrors(['password' => __('keyring::keyring.password_to_remove_last_factor')]);
    expect($totp->fresh())->not->toBeNull();

    $this->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => 'a password long enough alone'])->assertOk();
    expect($totp->fresh())->toBeNull();
});

it('validates a factor of the app\'s own against the body too', function () {
    Keyring::factors([Password::class, Totp::class, SmsCode::class]);
    Keyring::require(Requirement::aal2());
    Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'sms']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

    $this->post(route('keyring.login.verify', 'sms').'?code=123456')->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('reads a GET from its query string, which is all a GET has', function () {
    $get = Request::create('/callback?code=abc&state[]=x', 'GET');
    $json = Request::create('/callback?code=abc', 'GET', server: ['CONTENT_TYPE' => 'application/json'], content: '{"code":"from the body"}');

    expect(Input::get($get, 'code'))->toBe('abc')
        ->and(Input::text($get, 'state'))->toBe('')
        ->and(Input::get($json, 'code'))->toBe('abc')
        ->and(Input::all($get))->toBe(['code' => 'abc', 'state' => ['x']]);
});

it('reads a POST from its body alone, form or JSON', function () {
    $form = Request::create('/login?password=url&remember=1', 'POST', ['password' => 'body']);
    $json = Request::create('/login?password=url', 'POST', server: ['CONTENT_TYPE' => 'application/json'], content: '{"credential":{"id":"abc"}}');
    $spoofed = Request::create('/user/password?password=url', 'POST', ['_method' => 'PUT', 'current_password' => 'body']);

    expect(Input::get($form, 'password'))->toBe('body')
        ->and(Input::get($form, 'remember'))->toBeNull()
        ->and(Input::get($json, 'password'))->toBeNull()
        ->and(Input::get($json, 'credential'))->toBe(['id' => 'abc'])
        ->and(Input::get($spoofed, 'password'))->toBeNull()
        ->and(Input::text($spoofed, 'current_password'))->toBe('body');
});
