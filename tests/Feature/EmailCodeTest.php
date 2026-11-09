<?php

use Illuminate\Support\Facades\Notification;
use Keyring\Enums\Assurance;
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
    Keyring::factors([Password::class, Totp::class, EmailCode::asSecondFactor(), RecoveryCodes::class]);

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

it('keeps counting wrong guesses when a new code is sent', function () {
    config(['keyring.limits.per_account' => 100]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 4) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
    }

    Notification::fake();
    $this->post(route('keyring.login.send', 'email-code'))->assertSessionHas('status', 'code-sent');
    $newest = sentCode($this->user);

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000'])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => $newest])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);
    $this->assertGuest();
});

it('still signs in with a new code while guesses are left', function () {
    config(['keyring.limits.per_account' => 100]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 4) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000'])
            ->assertSessionHasErrors(['code' => __('keyring::keyring.invalid')]);
    }

    Notification::fake();
    $this->post(route('keyring.login.send', 'email-code'))->assertSessionHasNoErrors();

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user)])
        ->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('does not give guesses back when a code expires', function () {
    config(['keyring.limits.per_account' => 100, 'keyring.pending_login_ttl' => 3600]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 4) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
    }

    $this->travel(11)->minutes();
    $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);

    Notification::fake();
    $this->post(route('keyring.login.send', 'email-code'));

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000'])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);
    $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user)])
        ->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('makes the user start signing in again once the guesses run out', function () {
    config(['keyring.limits.per_account' => 100]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 5) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
    }

    $this->get(route('keyring.login.challenge'))
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('keyring::keyring.too_many_codes')]);

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user)])
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors('email');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

    Notification::fake();
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));
    $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user)])->assertRedirect('/dashboard');
});

it('sends no new code once the guesses run out', function () {
    config(['keyring.limits.per_account' => 100]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 5) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
    }

    Notification::fake();

    $this->post(route('keyring.login.send', 'email-code'))
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('keyring::keyring.too_many_codes')]);

    Notification::assertNothingSent();
    $this->assertGuest();
});

it('takes no other factor once a code has run out of guesses', function () {
    config(['keyring.limits.per_account' => 100]);
    emailAuthenticator($this->user);
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 5) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
    }

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);
    $this->assertGuest();
});

it('keeps counting against the account once the guesses run out', function () {
    config(['keyring.limits.per_account' => 6]);
    emailAuthenticator($this->user);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.send', 'email-code'));

    foreach (range(1, 5) as $guess) {
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
    }

    $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000'])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);

    $this->postJson(route('keyring.login.verify', 'email-code'), ['code' => '00000000'])->assertStatus(429);
});

it('restarts a step-up when its code runs out of guesses', function () {
    config(['keyring.limits.per_account' => 100]);
    emailAuthenticator($this->user);
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $this->inertia()->get(route('keyring.confirm.challenge', 'email-code'))->assertOk();
    $this->post(route('keyring.confirm.send', 'email-code'));

    foreach (range(1, 5) as $guess) {
        $this->post(route('keyring.confirm.verify', 'email-code'), ['code' => '00000000']);
    }

    $this->inertia()->get(route('keyring.confirm.challenge', 'email-code'))
        ->assertRedirect(route('keyring.confirm.challenge'))
        ->assertSessionHasErrors(['email' => __('keyring::keyring.too_many_codes')]);

    Notification::fake();
    $this->inertia()->get(route('keyring.confirm.challenge', 'email-code'))->assertOk();
    $this->post(route('keyring.confirm.send', 'email-code'));
    $this->post(route('keyring.confirm.verify', 'email-code'), ['code' => sentCode($this->user)])->assertSessionHasNoErrors();
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

it('does not send more codes for a new sign in', function () {
    emailAuthenticator($this->user);

    foreach (range(1, 3) as $send) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.send', 'email-code'))->assertSessionHasNoErrors();
    }

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.send', 'email-code'))->assertSessionHasErrors('code');
    Notification::assertSentToTimes($this->user, VerificationCode::class, 3);

    $this->travel(11)->minutes();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.send', 'email-code'))->assertSessionHasNoErrors();
});

it('limits how often starting an enrollment sends a code', function () {
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    foreach (range(1, 3) as $send) {
        $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
    }

    $this->postJson(route('keyring.authenticators.store', 'email-code'))
        ->assertTooManyRequests()
        ->assertJsonValidationErrors('code');
    Notification::assertSentToTimes($this->user, VerificationCode::class, 3);

    $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk();
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

it('keeps counting enrollment guesses when the enrollment starts again', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();

    foreach (range(1, 4) as $guess) {
        $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => '00000000'])->assertUnprocessable();
    }

    Notification::fake();
    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
    $newest = sentCode($this->user);

    $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => '00000000'])
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['code' => __('keyring::keyring.enrollment_too_many_codes')]);
    $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => $newest])->assertUnprocessable();

    Notification::fake();
    $this->postJson(route('keyring.authenticators.store', 'email-code'))
        ->assertUnprocessable()
        ->assertJsonValidationErrors(['code' => __('keyring::keyring.enrollment_too_many_codes')]);
    Notification::assertNothingSent();

    expect($this->user->keyring->refresh()->of('email-code'))->toBeEmpty();
});

it('enrolls with a new code while guesses are left', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();

    foreach (range(1, 4) as $guess) {
        $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => '00000000'])->assertUnprocessable();
    }

    Notification::fake();
    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => sentCode($this->user)])->assertOk();

    expect($this->user->keyring->refresh()->of('email-code'))->toHaveCount(1);
});

it('lets a used up enrollment start afresh once its 15 minutes have passed', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();

    foreach (range(1, 5) as $guess) {
        $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => '00000000'])->assertUnprocessable();
    }

    $this->travel(16)->minutes();
    $this->withAssurance(Assurance::AAL1);

    Notification::fake();
    $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
    $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => sentCode($this->user)])->assertOk();
});

it('only takes email codes as a second factor when the app accepts the risk', function () {
    Keyring::factors([Password::class, EmailCode::class]);

    expect(fn () => Keyring::registered())->toThrow(InvalidArgumentException::class, 'EmailCode::asSecondFactor()');
});
