<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Password as PasswordBroker;
use Illuminate\Testing\TestResponse;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Events\PasswordReset;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Sessions\SessionAssurance;
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

it('counts password guesses at login and when confirming together', function () {
    config(['keyring.limits.per_account' => 3]);
    $user = account('taylor@example.com');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $this->actingAs($user)->get(route('keyring.confirm.challenge'));
    $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
        ->assertSessionHasErrors('password');
    expect(session(\Keyring\Sessions\SessionAssurance::KEY))->toBeNull();
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

    $this->post('/login', ['email' => 'v4@example.com', 'password' => 'nope']);
    $error = $this->sessionErrors()->first('email');

    expect($error)->toContain('Too many');
});

it('counts spelling variants of the same address against one account limit', function () {
    config(['keyring.limits.per_account' => 2, 'keyring.limits.per_ip' => 100]);
    account('taylor@example.com');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $this->post('/login', ['email' => ' TÂYLOR@example.com ', 'password' => 'nope']);
    $error = $this->sessionErrors()->first('email');

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

it('lets the owner sign in from a known device while someone else is locked out', function () {
    config(['keyring.limits.per_account' => 3, 'keyring.limits.per_ip' => 100]);
    account('taylor@example.com');

    $device = $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->getCookie('keyring_device')->getValue();
    $this->post('/logout');

    foreach (range(1, 4) as $guess) {
        $this->withUnencryptedCookies([])->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    }

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $error = $this->sessionErrors()->first('email');
    expect($error)->toContain('Too many');

    $this->withCookie('keyring_device', $device)
        ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');
});

describe('a shared address', function () {
    beforeEach(function () {
        config(['keyring.limits.per_ip' => 3, 'keyring.limits.per_account' => 100]);
    });

    function fillAddress(): void
    {
        foreach (range(1, 3) as $guess) {
            test()->post('/login', ['email' => "someone{$guess}@example.com", 'password' => 'nope']);
        }
    }

    function deviceCookieFor(string $email): string
    {
        $device = test()->post('/login', ['email' => $email, 'password' => 'password'])->getCookie('keyring_device')->getValue();
        test()->post('/logout');
        test()->flushSession();

        return $device;
    }

    it('locks the address for longer each time one person reaches the limit', function () {
        account('neighbour@example.com');

        fillAddress();
        $this->travel(61)->seconds();
        fillAddress();
        $this->travel(61)->seconds();

        $this->post('/login', ['email' => 'neighbour@example.com', 'password' => 'password']);
        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();

        $this->travel(60)->seconds();

        $this->post('/login', ['email' => 'neighbour@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('never locks the address for more than fifteen minutes', function () {
        account('neighbour@example.com');

        foreach (range(1, 8) as $run) {
            fillAddress();

            $this->post('/login', ['email' => 'neighbour@example.com', 'password' => 'password']);
            expect($this->sessionErrors()->first('email'))->toContain('Too many');
            $this->assertGuest();

            $this->travel(901)->seconds();
        }

        $this->post('/login', ['email' => 'neighbour@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('lets an account through on its own known device while the address is used up', function () {
        account('taylor@example.com');
        $device = deviceCookieFor('taylor@example.com');

        fillAddress();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        expect($this->sessionErrors()->first('email'))->toContain('Too many');

        $this->withCookie('keyring_device', $device)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect('/dashboard');
    });

    it('does not let a device cookie for one account past the limit for another', function () {
        account('attacker@example.com');
        account('victim@example.com');
        $device = deviceCookieFor('attacker@example.com');

        fillAddress();

        $this->withCookie('keyring_device', $device)
            ->post('/login', ['email' => 'victim@example.com', 'password' => 'password']);

        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();
    });

    it('gives every device cookie of an account one count per address, so stolen cookies share it', function () {
        account('taylor@example.com');
        $first = deviceCookieFor('taylor@example.com');
        $second = deviceCookieFor('taylor@example.com');
        expect($first)->not->toBe($second);

        foreach ([$first, $first, $second] as $device) {
            $this->withCookie('keyring_device', $device)
                ->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])
                ->assertSessionHasErrors(['email' => __('auth.failed')]);
        }

        $this->withCookie('keyring_device', $second)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();

        $this->travel(61)->seconds();

        $this->withCookie('keyring_device', $first)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect('/dashboard');
    });

    it('does not count an attempt the address refused against the account', function () {
        config(['keyring.limits.per_account' => 2]);
        account('neighbour@example.com');

        fillAddress();
        $this->travel(50)->seconds();

        foreach (range(1, 3) as $retry) {
            $this->post('/login', ['email' => 'neighbour@example.com', 'password' => 'password']);
            expect($this->sessionErrors()->first('email'))->toContain('Too many');
        }

        // The address's minute is up, and the neighbour was never counted.
        $this->travel(11)->seconds();

        $this->post('/login', ['email' => 'neighbour@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('does not let a device cookie for a look-alike address past the limit', function () {
        account('victim@exämple.com');
        $device = deviceCookieFor('victim@exämple.com');

        fillAddress();

        $this->withCookie('keyring_device', $device)
            ->post('/login', ['email' => 'victim@example.com', 'password' => 'password']);

        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();

        // Its owner still gets through, however they type the address.
        $this->withCookie('keyring_device', $device)
            ->post('/login', ['email' => ' VICTIM@EXÄMPLE.COM ', 'password' => 'password'])
            ->assertRedirect('/dashboard');
    });

    it('treats another model\'s device with the same id as unknown on the second factor', function () {
        $user = account('taylor@example.com');
        $device = Keyring::deviceModel()::make(['token_hash' => Keyring::deviceModel()::hashToken($token = str_repeat('a', 40)), 'first_seen_at' => now()]);
        $device->authenticatable()->associate(staff());
        $device->save();

        $limits = Keyring::factor('totp')->limits(Request::create('/', 'POST', cookies: ['keyring_device' => $token]), Attempt::start(Purpose::Login, $user));

        expect(collect($limits)->pluck('key')->implode(' '))->not->toContain('|device|');
    });

    it('treats a device cookie like any other browser when devices are off', function () {
        account('taylor@example.com');
        $device = deviceCookieFor('taylor@example.com');

        withFeatures([]);
        fillAddress();

        $this->withCookie('keyring_device', $device)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();
    });
});

describe('failures in a row, however slowly they come', function () {
    beforeEach(function () {
        config(['keyring.limits.consecutive' => 3]);
        $this->user = account('taylor@example.com');
        $this->totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    });

    /**
     * A wrong code, or with none, the right one once it's later.
     */
    function guessTotp(?string $code = null): void
    {
        test()->travel(3)->minutes();
        test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        test()->post(route('keyring.login.verify', 'totp'), ['code' => $code ?? totpCode(test()->totp->secret)]);
    }

    it('refuses the factor at the cap, even with the right code', function () {
        guessTotp('000000');
        guessTotp('000000');
        guessTotp('000000');

        guessTotp();

        $this->assertGuest();
    });

    it('starts the count again after a success', function () {
        guessTotp('000000');
        guessTotp('000000');
        guessTotp();
        $this->assertAuthenticatedAs($this->user);
        $this->post('/logout');

        guessTotp('000000');
        guessTotp('000000');
        guessTotp();

        $this->assertAuthenticatedAs($this->user);
    });

    it('lets a password reset clear it for the password', function () {
        foreach (range(1, 3) as $guess) {
            $this->travel(3)->minutes();
            $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
        }

        $this->post(route('password.update'), [
            'token' => PasswordBroker::broker()->createToken($this->user),
            'email' => 'taylor@example.com',
            'password' => 'a brand new passphrase',
            'password_confirmation' => 'a brand new passphrase',
        ])->assertRedirect(route('login'));

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase'])
            ->assertRedirect(route('keyring.login.challenge'));
    });

    it('keeps a second factor refused through a password reset', function () {
        guessTotp('000000');
        guessTotp('000000');
        guessTotp('000000');

        $this->post(route('password.update'), [
            'token' => PasswordBroker::broker()->createToken($this->user),
            'email' => 'taylor@example.com',
            'password' => 'a brand new passphrase',
            'password_confirmation' => 'a brand new passphrase',
        ])->assertRedirect(route('login'));

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase']);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)]);

        $this->assertGuest();
    });

    it('keeps a count of its own for a browser the account has signed in from', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $device = $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->getCookie('keyring_device')->getValue();
        $this->post('/logout');

        guessTotp('000000');
        guessTotp('000000');
        guessTotp('000000');
        guessTotp();
        $this->assertGuest();

        $this->withCookie('keyring_device', $device);
        guessTotp('000000');
        guessTotp('000000');
        guessTotp();

        $this->assertAuthenticatedAs($this->user);
    });
});

it('allows a reloading login page its passkey options, and stops a flood of them per address', function () {
    foreach (range(1, 60) as $reload) {
        $this->getJson(route('keyring.login.options', 'passkey'))->assertOk();
    }

    $this->getJson(route('keyring.login.options', 'passkey'))->assertTooManyRequests();

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])
        ->getJson(route('keyring.login.options', 'passkey'))
        ->assertOk();
});

describe('a completed password reset', function () {
    beforeEach(function () {
        config(['keyring.limits.per_account' => 3, 'keyring.limits.per_ip' => 100]);
        $this->user = account('taylor@example.com');
    });

    function guessPassword(int $times, string $email = 'taylor@example.com', string $ip = '203.0.113.66'): void
    {
        foreach (range(1, $times) as $guess) {
            test()->withServerVariables(['REMOTE_ADDR' => $ip])->post('/login', ['email' => $email, 'password' => 'nope']);
        }
    }

    function completeReset(User $user): void
    {
        test()->post(route('password.update'), [
            'token' => PasswordBroker::broker()->createToken($user),
            'email' => $user->email,
            'password' => 'a brand new passphrase',
            'password_confirmation' => 'a brand new passphrase',
        ])->assertRedirect(route('login'));
    }

    function signInFrom(string $ip, string $email = 'taylor@example.com', string $password = 'a brand new passphrase'): TestResponse
    {
        return test()->withServerVariables(['REMOTE_ADDR' => $ip])->post('/login', ['email' => $email, 'password' => $password]);
    }

    it('lets the owner in straight away from elsewhere, however the guesses spelled the address', function () {
        guessPassword(3, ' TÂYLOR@example.com ');

        signInFrom('198.51.100.7', password: 'password')->assertSessionHasErrors('email');
        expect($this->sessionErrors()->first('email'))->toContain('Too many');

        completeReset($this->user);

        signInFrom('198.51.100.7')->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
    });

    it('starts the lockout escalation over', function () {
        guessPassword(3);
        $this->travel(61)->seconds();
        guessPassword(3);

        completeReset($this->user);

        // The first lock again, one minute. Escalation would make this four.
        guessPassword(3);
        $this->travel(61)->seconds();

        signInFrom('198.51.100.7')->assertRedirect('/dashboard');
    });

    it('forgets failures that had not reached a lock yet', function () {
        guessPassword(2);

        completeReset($this->user);

        guessPassword(2);

        signInFrom('198.51.100.7')->assertRedirect('/dashboard');
    });

    it('clears a known device\'s bucket under the typed username', function () {
        $device = $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->getCookie('keyring_device')->getValue();
        $this->post('/logout');

        $this->withCookie('keyring_device', $device);
        guessPassword(3);
        signInFrom('203.0.113.66', password: 'password')->assertSessionHasErrors('email');
        expect($this->sessionErrors()->first('email'))->toContain('Too many');

        completeReset($this->user);

        signInFrom('203.0.113.66')->assertRedirect('/dashboard');
    });

    it('leaves a second factor locked, because a reset only proves the mailbox', function () {
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        foreach (range(1, 3) as $guess) {
            $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);
        }

        completeReset($this->user);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase']);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)]);

        $this->assertGuest();
    });

    it('leaves the per-ip limit in place', function () {
        config(['keyring.limits.per_ip' => 2, 'keyring.limits.per_account' => 100]);

        guessPassword(2);

        completeReset($this->user);

        signInFrom('203.0.113.66')->assertSessionHasErrors('email');
        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();

        signInFrom('198.51.100.7')->assertRedirect('/dashboard');
    });

    it('leaves other accounts locked', function () {
        account('other@example.com');
        guessPassword(3, 'other@example.com');

        completeReset($this->user);

        signInFrom('198.51.100.7', 'other@example.com', 'password')->assertSessionHasErrors('email');
        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();
    });

    it('keeps throttling after the reset', function () {
        completeReset($this->user);

        guessPassword(3);

        signInFrom('198.51.100.7')->assertSessionHasErrors('email');
        expect($this->sessionErrors()->first('email'))->toContain('Too many');
        $this->assertGuest();
    });

    it('logs that it cleared them', function () {
        completeReset($this->user);

        expect(SecurityEvent::query()->where('type', 'password_reset')->sole()->meta)->toBe(['sign_in_locks_cleared' => true]);
    });

    it('clears another identifier the finder accepts, when the app names it', function () {
        config(['keyring.limits.consecutive' => 3]);
        $this->user->update(['name' => 'tay']);

        Keyring::findUsersUsing(fn (Request $request) => User::query()
            ->where('email', $request->input('email'))
            ->orWhere('name', $request->input('email'))
            ->first());
        // The null: identifiers can be optional, and a missing one mustn't break the reset.
        Event::listen(fn (PasswordReset $event) => EnsureNotThrottled::clearAccount($event->user, $event->user->name, null));

        guessPassword(3, 'tay');

        signInFrom('198.51.100.7', 'tay', 'password')->assertSessionHasErrors('email');
        expect($this->sessionErrors()->first('email'))->toContain('Too many');

        completeReset($this->user);

        signInFrom('198.51.100.7', 'tay')->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
    });

    it('still clears them with the devices and security log features off', function () {
        withFeatures([Features::resetPasswords()]);

        guessPassword(3);

        completeReset($this->user);

        signInFrom('198.51.100.7')->assertRedirect('/dashboard');
    });
});
