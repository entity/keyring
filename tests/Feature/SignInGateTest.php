<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SingleSignOn;
use Keyring\Tests\Fixtures\User;

// An app keeps some accounts out, here ones whose name it has changed to
// "Banned". However they come, they're answered like nobody at all.
beforeEach(function () {
    Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, SingleSignOn::class]);
    Keyring::allowSignInWhen(fn (User $user) => $user->name !== 'Banned');

    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    $this->user = taylor();
});

function ban(User $user): void
{
    $user->forceFill(['name' => 'Banned'])->save();
}

it('signs in an account the app allows', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    $this->get('/home')->assertOk();
});

it('answers the right password like a wrong one', function () {
    ban($this->user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
});

it('spends a hash on a banned account, as checking its password would', function () {
    ban($this->user);

    Hash::spy();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    Hash::shouldNotHaveReceived('check');
    Hash::shouldHaveReceived('make')->once();
});

it('refuses a passkey', function () {
    $key = new VirtualAuthenticator;
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');
    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();
    $this->post('/logout');

    ban($this->user);

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($this->getJson(route('keyring.login.options', 'passkey'))->json('options'))])
        ->assertSessionHasErrors();

    $this->assertGuest();
});

it('refuses a factor of the app\'s own', function () {
    Route::middleware('web')->post('/sso/callback', fn (Request $request) => Keyring::attempt($request, 'sso'));
    SingleSignOn::$vouchedFor = 'taylor@example.com';
    ban($this->user);

    $this->post('/sso/callback')->assertSessionHasErrors();

    $this->assertGuest();
});

it('ends a sign in that was waiting for its second factor', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    ban($this->user);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect(route('login'));

    $this->assertGuest();
});

it('signs out a session that is already signed in, and says why in the log', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get('/home')->assertOk();

    ban($this->user);
    Auth::forgetGuards();

    $this->get('/home')->assertRedirect('/login');
    $this->assertGuest();

    expect(app(SessionRegistry::class)->forUser($this->user))->toBeEmpty()
        ->and(SecurityEvent::query()->where('type', 'session_ended')->sole()->meta['reason'])->toBe('not_allowed');
});

it('refuses a "remember me" cookie', function () {
    $response = $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
    $cookies = collect([Auth::guard()->getRecallerName(), 'keyring_remember'])
        ->mapWithKeys(fn (string $name) => [$name => $response->getCookie($name)->getValue()])
        ->all();

    ban($this->user);
    $this->flushSession();
    Auth::forgetGuards();

    $this->withCookies($cookies)->get('/home')->assertRedirect('/login');
    $this->assertGuest();
});

it('signs out a session the app started itself', function () {
    ban($this->user);

    $this->actingAs($this->user)->get('/home')->assertRedirect('/login');
});

it('leaves a new account that may not sign in yet signed out after registering', function () {
    // Where registering signs new users in at all.
    revealTakenAddresses();
    Keyring::allowSignInWhen(fn (User $user) => $user->email_verified_at !== null);

    $this->post('/register', ['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'a-brand-new-long-password-1', 'password_confirmation' => 'a-brand-new-long-password-1'])
        ->assertRedirect(route('login'));

    $this->assertGuest();
    expect(User::query()->where('email', 'abigail@example.com')->exists())->toBeTrue();
});

it('still lets an account that may not sign in reset its password, without signing it in', function () {
    ban($this->user);

    $this->post('/forgot-password', ['email' => 'taylor@example.com'])->assertSessionHasNoErrors();

    $this->assertGuest();
});
