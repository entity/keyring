<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Factor;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Notifications\VerificationCode;
use Keyring\Risk\Action;
use Keyring\Risk\Signals\NewDevice;
use Keyring\Sessions\SessionAssurance;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Notification::fake();
    Keyring::factors([Password::class, Totp::class, EmailCode::asExtraStep(), RecoveryCodes::class]);

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
    config(['keyring.pending_logins.keep_for' => 3600]);
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
    config(['keyring.limits.per_account' => 100, 'keyring.pending_logins.keep_for' => 3600]);
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
    // An account with an authenticator app is only offered a code where the
    // policy says any second step will do.
    Keyring::require(Requirement::steps(2));
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
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

    // A code alone confirms nothing, so the step-up is one that asks for it
    // beside the password: adding a sign-in method.
    $this->post(route('keyring.authenticators.store', 'totp'))->assertRedirect(route('keyring.confirm.challenge'));
    $this->inertia()->get(route('keyring.confirm.challenge', 'email-code'))->assertOk();
    $this->post(route('keyring.confirm.send', 'email-code'));

    foreach (range(1, 5) as $guess) {
        $this->post(route('keyring.confirm.verify', 'email-code'), ['code' => '00000000']);
    }

    $this->inertia()->get(route('keyring.confirm.challenge', 'email-code'))
        ->assertRedirect(route('keyring.confirm.challenge'))
        ->assertSessionHasErrors(['password' => __('keyring::keyring.too_many_codes')]);

    Notification::fake();
    $this->post(route('keyring.authenticators.store', 'totp'))->assertRedirect(route('keyring.confirm.challenge'));
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

    expect(fn () => Keyring::registered())->toThrow(InvalidArgumentException::class, 'EmailCode::asExtraStep()');
});

it('refuses a code shorter than six digits, the least that resists guessing', function (int $length) {
    EmailCode::asExtraStep(length: $length);
})->with([1, 5])->throws(LogicException::class, 'Keyring refuses codes shorter than 6 digits');

it('refuses a code that lasts longer than ten minutes', function (string $expireAfter) {
    EmailCode::asExtraStep(expireAfter: $expireAfter);
})->with(['601', '11m', '30d'])->throws(LogicException::class, 'Keyring refuses a code that lasts longer than 600 seconds');

it('refuses a code that lasts no time at all', function () {
    EmailCode::asExtraStep(expireAfter: '0s');
})->throws(LogicException::class, 'or no time at all');

it('takes six digits and ten minutes, the edges of what it allows', function () {
    Keyring::factors([Password::class, EmailCode::asExtraStep(length: 6, expireAfter: '10m')]);

    expect(Keyring::registered()->keys()->all())->toBe(['password', 'email-code']);
});

// Laravel's "cookie" session driver keeps the session in the browser, which
// can send back an earlier copy of it. A code's state is kept on the server,
// so what the copy says about a code changes nothing.
describe('a browser that sends back an earlier copy of its session', function () {
    beforeEach(function () {
        config(['keyring.limits.per_account' => 100]);
    });

    it('cannot sign in with a code a second time', function () {
        emailAuthenticator($this->user);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.send', 'email-code'));
        $code = sentCode($this->user);
        $unspent = session()->all();

        $this->post(route('keyring.login.verify', 'email-code'), ['code' => $code])->assertRedirect('/dashboard');
        $this->post('/logout');

        sendBackSession($unspent);

        $this->post(route('keyring.login.verify', 'email-code'), ['code' => $code])
            ->assertSessionHasErrors(['code' => __('keyring::keyring.invalid')]);
        $this->assertGuest();
    });

    it('cannot confirm with a code a second time', function () {
        emailAuthenticator($this->user);
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

        // A code alone confirms nothing, so the step-up is one that asks for
        // it beside the password: adding a sign-in method.
        $this->post(route('keyring.authenticators.store', 'totp'))->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.send', 'email-code'));
        $code = sentCode($this->user);
        $unspent = session()->all();

        $this->post(route('keyring.confirm.verify', 'email-code'), ['code' => $code])->assertSessionHasNoErrors();

        sendBackSession($unspent);

        $this->actingAs($this->user)->post(route('keyring.confirm.verify', 'email-code'), ['code' => $code])
            ->assertSessionHasErrors(['code' => __('keyring::keyring.invalid')]);
    });

    it('cannot enroll with a code a second time', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
        $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
        $code = sentCode($this->user);
        $unspent = session()->all();

        $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => $code])->assertOk();
        // Removed again, with the recovery codes that came with it.
        Authenticator::query()->delete();
        $this->user->keyring->refresh();

        sendBackSession($unspent);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => $code])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['code' => __('keyring::keyring.invalid')]);

        expect($this->user->keyring->refresh()->of('email-code'))->toBeEmpty();
    });

    it('does not get its wrong guesses back', function () {
        emailAuthenticator($this->user);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.send', 'email-code'));
        $code = sentCode($this->user);
        $unguessed = session()->all();

        foreach (range(1, 4) as $guess) {
            $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000'])
                ->assertSessionHasErrors(['code' => __('keyring::keyring.invalid')]);
        }

        sendBackSession($unguessed);

        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000'])
            ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);

        sendBackSession($unguessed);

        $this->post(route('keyring.login.verify', 'email-code'), ['code' => $code])
            ->assertSessionHasErrors(['code' => __('keyring::keyring.too_many_codes')]);
        $this->assertGuest();
    });

    it('is sent no new code once the guesses have run out', function () {
        emailAuthenticator($this->user);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.send', 'email-code'));
        $unguessed = session()->all();

        foreach (range(1, 5) as $guess) {
            $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);
        }

        sendBackSession($unguessed);
        Notification::fake();

        $this->post(route('keyring.login.send', 'email-code'))
            ->assertRedirect(route('login'))
            ->assertSessionHasErrors(['email' => __('keyring::keyring.too_many_codes')]);

        Notification::assertNothingSent();
    });

    it('cannot use a code that a newer one replaced', function () {
        emailAuthenticator($this->user);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.send', 'email-code'));
        $first = sentCode($this->user);
        $beforeResend = session()->all();

        Notification::fake();
        $this->post(route('keyring.login.send', 'email-code'));
        $second = sentCode($this->user);

        sendBackSession($beforeResend);

        $this->post(route('keyring.login.verify', 'email-code'), ['code' => $first])->assertSessionHasErrors('code');
        $this->assertGuest();

        $this->post(route('keyring.login.verify', 'email-code'), ['code' => $second])->assertRedirect('/dashboard');
    });

    it('does not get its wrong enrollment guesses back', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);
        $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
        $code = sentCode($this->user);
        $unguessed = session()->all();

        foreach (range(1, 5) as $guess) {
            $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => '00000000'])->assertUnprocessable();
        }

        sendBackSession($unguessed);

        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)
            ->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => $code])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['code' => __('keyring::keyring.enrollment_too_many_codes')]);

        expect($this->user->keyring->refresh()->of('email-code'))->toBeEmpty();
    });

    it('finds nothing of a code in the session to send back', function () {
        emailAuthenticator($this->user);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.send', 'email-code'));
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => '00000000']);

        $attempt = json_decode(Crypt::decryptString(session('keyring.attempt.login')), true);

        expect($attempt['state'])->toBe([]);
    });
});

// NIST SP 800-63B-4 doesn't take email as an authenticator (Sec. 3.1.3.1),
// so a code is a step an app may ask for and never a second factor.
describe('a step, not a factor', function () {
    beforeEach(function () {
        Route::middleware(['web', 'auth', 'keyring:aal2'])->get('/billing', fn () => 'billing');
        config(['keyring.enrollment_url' => '/settings/security']);
    });

    /**
     * Sign in with the password and the code emailed for it.
     */
    function signInWithEmailedCode(array $extra = []): TestResponse
    {
        test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
        test()->post(route('keyring.login.send', 'email-code'));

        return test()->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode(test()->user), ...$extra]);
    }

    it('leaves a session that proved a password and a code at aal1', function () {
        emailAuthenticator($this->user);

        signInWithEmailedCode()->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and(app(SessionRegistry::class)->forUser($this->user)->sole()->assurance)->toBe(Assurance::AAL1);
    });

    it('doesn\'t let a code satisfy keyring:aal2, and sends the user to add a real second factor', function () {
        emailAuthenticator($this->user);
        signInWithEmailedCode();

        $this->get('/billing')->assertRedirect('/settings/security')->assertSessionHas('status', 'enroll-first');
        $this->getJson('/billing')->assertForbidden()->assertJsonPath('status', 'enroll-first');
    });

    it('doesn\'t count as a second factor for the account', function () {
        emailAuthenticator($this->user);
        $keyring = $this->user->keyring;

        expect($keyring->hasSecondFactor())->toBeFalse()
            ->and($keyring->has(Category::Possession))->toBeFalse()
            ->and($keyring->has(Category::Address))->toBeTrue()
            ->and($keyring->canMeet(Requirement::aal2()))->toBeFalse()
            ->and($keyring->canMeet(Requirement::steps(2)))->toBeTrue()
            ->and($keyring->hasFactorToRecover())->toBeFalse();
    });

    it('refuses an account with only a code where the policy asks for two factors outright', function () {
        Keyring::require(Requirement::aal2());
        emailAuthenticator($this->user);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $this->get(route('keyring.login.challenge'))
            ->assertRedirect('/login')
            ->assertSessionHasErrors(['email' => __('keyring::keyring.unavailable')]);
        $this->assertGuest();
    });

    it('signs in with a password and a code where the policy asks for two steps', function () {
        Keyring::require(Requirement::steps(2));
        emailAuthenticator($this->user);

        signInWithEmailedCode()->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
    });

    it('isn\'t offered at sign in to an account that has a real second factor', function () {
        emailAuthenticator($this->user);
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $this->inertia()->get(route('keyring.login.challenge'))
            ->assertJsonPath('props.factor', 'totp')
            ->assertJsonPath('props.alternatives', []);

        $this->post(route('keyring.login.send', 'email-code'))->assertNotFound();
    });

    it('is asked for when risk wants more of an account with nothing stronger', function () {
        Keyring::require(Requirement::aal1());
        Keyring::risk()->signals([NewDevice::class])->respond(fn () => Action::stepUp());
        emailAuthenticator($this->user);

        signInWithEmailedCode()->assertRedirect('/dashboard');
    });

    it('doesn\'t earn trust for the device, or offer to', function () {
        emailAuthenticator($this->user);
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.canTrustDevice', false);
        $this->post(route('keyring.login.send', 'email-code'));
        $this->post(route('keyring.login.verify', 'email-code'), ['code' => sentCode($this->user), 'trust' => true])
            ->assertRedirect('/dashboard');

        expect(Device::sole()->isTrusted())->toBeFalse();
    });

    it('comes with no recovery codes, and can\'t be given any', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

        $this->postJson(route('keyring.authenticators.store', 'email-code'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'email-code'), ['code' => sentCode($this->user)])
            ->assertOk()
            ->assertJsonMissingPath('recoveryCodes');

        $email = $this->user->keyring->refresh()->of('email-code')->sole();

        $this->verifiedWith($email)->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))
            ->assertJsonValidationErrors(['authenticator' => __('keyring::keyring.recovery_needs_second_factor')]);

        expect($this->user->keyring->refresh()->of('recovery'))->toBeEmpty();
    });

    it('asks an account with only a code for it before adding a real second factor, which it can', function () {
        emailAuthenticator($this->user);
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

        $this->postJson(route('keyring.authenticators.store', 'totp'))->assertStatus(423);

        // The password alone isn't what signing in asks of this account.
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
            ->assertRedirect(route('keyring.confirm.challenge'));
        $this->post(route('keyring.confirm.send', 'email-code'));
        $this->post(route('keyring.confirm.verify', 'email-code'), ['code' => sentCode($this->user)])->assertSessionHasNoErrors();

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'))->assertOk()->json('enrollment.secret');
        $response = $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

        expect($response->json('recoveryCodes'))->toHaveCount(8)
            ->and($this->user->keyring->refresh()->hasSecondFactor())->toBeTrue();
    });

    it('doesn\'t stand in for the possession factor a fresh verification asks of an account that has one', function () {
        emailAuthenticator($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

        $this->post(route('keyring.authenticators.store', 'totp'))->assertRedirect(route('keyring.confirm.challenge'));

        $this->inertia()->get(route('keyring.confirm.challenge'))
            ->assertJsonPath('props.factor', 'totp')
            ->assertJsonPath('props.alternatives.0.factor', 'password')
            ->assertJsonMissingPath('props.alternatives.1');

        $this->post(route('keyring.confirm.send', 'email-code'))->assertNotFound();

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertSessionHasNoErrors();
        $this->post(route('keyring.authenticators.store', 'totp'))->assertSessionHas('status', 'enrollment-started');
    });

    it('takes the recovery codes with it when the last real second factor is removed', function () {
        emailAuthenticator($this->user);
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();
        Keyring::withoutProtection(fn () => $this->user->update(['password' => 'a long enough passphrase']));

        $this->actingAs($this->user)->verifiedWith($totp)
            ->deleteJson(route('keyring.authenticators.destroy', $totp->id), ['password' => 'a long enough passphrase'])
            ->assertOk();

        expect($this->user->keyring->refresh()->all()->pluck('factor')->all())->toBe(['password', 'email-code']);
    });

    it('asks an account left with a code and recovery codes for the emailed code, not a recovery code', function () {
        emailAuthenticator($this->user);
        Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        // A recovery code is a factor, so it will do in the code's place.
        $this->inertia()->get(route('keyring.login.challenge'))
            ->assertJsonPath('props.factor', 'email-code')
            ->assertJsonPath('props.alternatives.0.factor', 'recovery');
    });

    it('lets a custom factor say the same about itself', function () {
        Keyring::factors([Password::class, Totp::class, MagicWord::class]);
        Authenticator::factory()->for($this->user, 'authenticatable')->create(['factor' => 'magic-word', 'name' => 'Magic word', 'secret' => 'please']);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
        $this->post(route('keyring.login.verify', 'magic-word'), ['code' => 'please'])->assertRedirect('/dashboard');

        expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and($this->user->keyring->hasSecondFactor())->toBeFalse();
    });
});

/**
 * A step an app asks for that is no authenticator, as a custom factor says it.
 */
class MagicWord extends Factor
{
    public function key(): string
    {
        return 'magic-word';
    }

    public function categories(Authenticator $authenticator): array
    {
        return [Category::Address];
    }

    public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
    {
        return hash_equals((string) $authenticator->secret, (string) $request->input('code')) ? $this->verified($authenticator) : null;
    }
}
