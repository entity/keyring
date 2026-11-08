<?php

use Illuminate\Support\Facades\Notification;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Models\Authenticator;
use Keyring\Notifications\VerificationCode;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Notification::fake();
    Keyring::factors([Password::class, Totp::class, EmailCode::class, RecoveryCodes::class]);

    $this->user = taylor();
});

function emailAuthenticator(User $user): Authenticator
{
    return Authenticator::factory()->for($user, 'authenticatable')->create([
        'factor' => 'email-code',
        'name' => 'Email',
        'secret' => null,
    ]);
}

function sentCode(User $user): string
{
    $code = null;

    Notification::assertSentTo($user, VerificationCode::class, function (VerificationCode $notification) use (&$code) {
        $code = $notification->code;

        return true;
    });

    return $code;
}

it('only sends a code when asked, not when the page is viewed', function () {
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.factor', 'email-code')
        ->assertJsonPath('props.challenge.sent', false)
        ->assertJsonPath('props.authenticator.hint', 't•••@example.com');

    Notification::assertNothingSent();

    $this->post(route('keyring.login.send', 'email-code'))->assertSessionHas('status', 'code-sent');

    $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.challenge.sent', true);

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('sends eight digit codes that expire', function () {
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    $code = sentCode($this->user);
    expect($code)->toMatch('/^\d{8}$/');

    $this->travel(9)->minutes();
    $this->post(route('keyring.login.verify', 'email-code'), ['code' => $code]);
    $this->assertAuthenticated();
});

it('rejects an expired code', function () {
    config(['keyring.pending_login_ttl' => 3600]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    $this->travel(11)->minutes();

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user)])
        ->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('burns the code after too many wrong guesses', function () {
    config(['keyring.limits.per_account' => 100]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 5) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
    }

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user)])
        ->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('replaces the old code when resending', function () {
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));

    $this->post(route('keyring.login.send', 'email-code'));
    $first = sentCode($this->user);
    Notification::fake();
    $this->post(route('keyring.login.send', 'email-code'));
    $second = sentCode($this->user);

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => $first])->assertSessionHasErrors('code');
    $this->post(route('keyring.login.verify', 'email-code'), ['code' => $second])->assertRedirect('/dashboard');
});

it('limits how often codes are sent', function () {
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));

    foreach (range(1, 3) as $send) {
        $this->post(route('keyring.login.send', 'email-code'))->assertSessionHasNoErrors();
    }

    $this->post(route('keyring.login.send', 'email-code'))->assertSessionHasErrors('code');
});

it('enrolls email codes by confirming a sent code', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk()->assertJsonPath('enrollment.sent', true);

    $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => sentCode($this->user)])
        ->assertOk()
        ->assertJsonPath('authenticator.name', 'Email');

    expect($this->user->keyring->refresh()->of('email-code'))->toHaveCount(1);
});

it('burns the enrollment code after too many wrong guesses', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();

    foreach (range(1, 5) as $guess) {
        $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => '00000000'])->assertUnprocessable();
    }

    $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => sentCode($this->user)])->assertUnprocessable();

    expect($this->user->keyring->refresh()->of('email-code'))->toBeEmpty();
});
