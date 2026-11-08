<?php

use Illuminate\Http\Request;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Keyring::factors([Password::class, Totp::class, WebAuthn::passkeys(), RecoveryCodes::class]);
});

function account(string $email): User
{
    return User::create(['name' => 'Someone', 'email' => $email, 'password' => 'password', 'email_verified_at' => now()]);
}

it('does not let junk passkey requests lock everyone out of passkey sign in', function () {
    $user = account('taylor@example.com');
    $key = new VirtualAuthenticator;

    test()->actingAs($user)->withAssurance(Assurance::AAL1);
    $options = test()->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');
    test()->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();
    test()->post('/logout');

    foreach (range(1, 6) as $attempt) {
        $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])
            ->post(route('keyring.login.factor', 'passkey'), ['credential' => '{}']);
    }

    $options = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])
        ->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');
});

it('does not reset the per-ip counter when the attacker signs in to their own account', function () {
    config(['keyring.limits.per_ip' => 3, 'keyring.limits.per_account' => 100]);
    $attacker = account('attacker@example.com');
    Authenticator::factory()->totp()->for($attacker, 'authenticatable')->create();

    $this->post('/login', ['email' => 'v1@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'v2@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'attacker@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));
    $this->post('/login', ['email' => 'v3@example.com', 'password' => 'nope']);

    $error = $this->post('/login', ['email' => 'v4@example.com', 'password' => 'nope'])
        ->getSession()->get('errors')->first('email');

    expect($error)->toContain('Too many');
});

it('counts spelling variants of the same address against one account limit', function () {
    config(['keyring.limits.per_account' => 2, 'keyring.limits.per_ip' => 100]);
    account('taylor@example.com');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $error = $this->post('/login', ['email' => ' TÂYLOR@example.com ', 'password' => 'nope'])
        ->getSession()->get('errors')->first('email');

    expect($error)->toContain('Too many');
});

it('counts overlapping attempts before verifying them', function () {
    config(['keyring.limits.per_account' => 5, 'keyring.limits.per_ip' => 100]);
    account('taylor@example.com');

    $step = app(EnsureNotThrottled::class);
    $verified = 0;
    $request = Request::create('/login', 'POST', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $attempt = function () use (&$attempt, &$verified, $step, $request): Context {
        static $depth = 0;

        return $step->handle(new Context($request, Purpose::Login, Keyring::factor('password')), function (Context $context) use (&$attempt, &$verified, &$depth) {
            $verified++;

            // Simulate nine more requests arriving while this one is still being verified.
            if ($depth++ === 0) {
                foreach (range(1, 9) as $overlapping) {
                    $attempt();
                }
            }

            return $context->fail();
        });
    };

    $attempt();

    expect($verified)->toBe(5);
});

it('still escalates lockouts after a burst', function () {
    config(['keyring.limits.per_account' => 2, 'keyring.limits.per_ip' => 100]);
    account('taylor@example.com');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertSessionHasErrors('email');
    $this->assertGuest();

    $this->travel(61)->seconds();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
});

it('does not count successful sign-ins against the ip limit', function () {
    config(['keyring.limits.per_ip' => 3, 'keyring.limits.per_account' => 100]);
    account('taylor@example.com');

    foreach (range(1, 5) as $signIn) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
        $this->post('/logout');
    }

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])
        ->assertSessionHasErrors(['email' => __('auth.failed')]);
});
