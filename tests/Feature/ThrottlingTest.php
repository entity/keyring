<?php

declare(strict_types=1);

use App\Notifications\Keyring\AccountLocked as AccountLockedNotice;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password as PasswordBroker;
use Illuminate\Support\Timebox;
use Illuminate\Testing\TestResponse;
use Keyring\Enums\Assurance;
use Keyring\Enums\Purpose;
use Keyring\Events\AccountLocked;
use Keyring\Events\FactorFailed;
use Keyring\Events\Lockout;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\Login\Attempt;
use Keyring\Models\Authenticator;
use Keyring\Models\SecurityEvent;
use Keyring\Pipeline\AccountLimit;
use Keyring\Pipeline\Context;
use Keyring\Pipeline\Steps\EnsureNotThrottled;
use Keyring\Sessions\SessionAssurance;
use Keyring\Support\Throttle;
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

    $options = $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.2'])->getJson(route('keyring.login.options', 'passkey'))->json('options');

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
    expect(session(SessionAssurance::KEY))->toBeNull();
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

it('counts every way of typing an account\'s username against that account\'s limit', function () {
    config(['keyring.limits.per_account' => 2, 'keyring.limits.per_ip' => 100]);
    account('taylor@example.com');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $this->post('/login', ['email' => ' TAYLOR@Example.com ', 'password' => 'nope']);
    $error = $this->sessionErrors()->first('email');

    expect($error)->toContain('Too many');
});

it('does not let signing in to a lookalike account clear another account\'s limits', function () {
    config(['keyring.limits.per_account' => 5, 'keyring.limits.consecutive' => 10, 'keyring.limits.per_ip' => 1000]);
    account('victim@example.com');
    // Another account where the database tells accents apart.
    User::create(['name' => 'Mallory', 'email' => 'vìctim@example.com', 'password' => 'a passphrase of her own', 'email_verified_at' => now()]);

    $statuses = [];

    foreach (range(1, 3) as $round) {
        foreach (range(1, 4) as $guess) {
            $statuses[] = $this->postJson('/login', ['email' => 'victim@example.com', 'password' => "guess {$round} {$guess}"])->status();
        }

        $this->postJson('/login', ['email' => 'vìctim@example.com', 'password' => 'a passphrase of her own'])->assertOk();
        $this->post('/logout');
        $this->flushSession();
    }

    // Five a minute, whoever else signs in between them.
    expect(array_count_values($statuses))->toBe([422 => 5, 429 => 7]);
})->skip(fn () => databaseIgnoresAccents(), 'The database treats the two addresses as one, so both accounts can\'t exist.');

it('limits guesses at a username nobody has like guesses at a real one', function () {
    config(['keyring.limits.per_account' => 2, 'keyring.limits.per_ip' => 100]);

    $statuses = array_map(
        fn () => $this->postJson('/login', ['email' => 'nobody@example.com', 'password' => 'nope'])->status(),
        range(1, 3),
    );

    expect($statuses)->toBe([422, 422, 429]);
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

it('does not start the next minute below zero when a sign in outlasts its count', function () {
    config(['keyring.limits.per_ip' => 2, 'keyring.limits.per_account' => 100]);
    account('taylor@example.com');

    foreach (range(1, 3) as $signIn) {
        $limits = Keyring::factor('password')->limits(Request::create('/login', 'POST', ['email' => 'taylor@example.com']), null);
        app(Throttle::class)->hit($limits);

        // The minute ends while the password is being checked.
        $this->travel(61)->seconds();
        app(Throttle::class)->succeeded($limits);
    }

    foreach (range(1, 2) as $guess) {
        $this->post('/login', ['email' => "someone{$guess}@example.com", 'password' => 'nope'])->assertSessionHasErrors(['email' => __('auth.failed')]);
    }

    $this->post('/login', ['email' => 'someone3@example.com', 'password' => 'nope'])->assertSessionHasErrors('email');
    expect(session('errors')->first('email'))->toContain('Too many');
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
    })->skip(fn () => databaseIgnoresAccents(), 'The database treats the two addresses as one account, whose device this is.');

    it('treats another model\'s device with the same id as unknown on the second factor', function () {
        $user = account('taylor@example.com');
        $device = Keyring::deviceModel()::make(['token_hash' => Keyring::deviceModel()::hashToken($token = str_repeat('a', 40)), 'first_seen_at' => now()]);
        $device->authenticatable()->associate(staff());
        $device->save();

        $limits = Keyring::factor('totp')->limits(Request::create('/', 'POST', cookies: ['keyring_device' => $token]), Attempt::start(Purpose::Login, $user));

        expect(collect($limits)->pluck('key')->implode(' '))->not->toContain('|known');
    });

    // The limits are worked out before the timebox opens, so what they
    // cost can't depend on whether the username found anyone.
    it('runs the same queries for a real username and an unknown one, however many accounts share the cookie', function () {
        $owner = account('taylor@example.com');
        $token = str_repeat('a', 40);

        foreach ([$owner, account('abigail@example.com'), account('jess@example.com')] as $user) {
            $device = Keyring::deviceModel()::make(['token_hash' => Keyring::deviceModel()::hashToken($token), 'first_seen_at' => now()]);
            $device->authenticatable()->associate($user);
            $device->save();
        }

        $queries = function (string $email) use ($token): int {
            DB::flushQueryLog();
            Keyring::factor('password')->limits(Request::create('/login', 'POST', ['email' => $email], ['keyring_device' => $token]), null);

            return count(DB::getQueryLog());
        };

        DB::enableQueryLog();

        expect($queries('taylor@example.com'))->toBe($queries('nobody@example.com'));

        $limits = Keyring::factor('password')->limits(Request::create('/login', 'POST', ['email' => 'taylor@example.com'], ['keyring_device' => $token]), null);

        expect(collect($limits)->pluck('key')->implode(' '))->toContain('|known');
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
        guessPassword(3, ' TAYLOR@Example.com ');

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

    it('clears them whichever of the account\'s identifiers the guesses were typed with', function () {
        config(['keyring.limits.consecutive' => 3]);
        $this->user->update(['name' => 'tay']);

        Keyring::findUsersUsing(fn (Request $request) => User::query()
            ->where('email', $request->input('email'))
            ->orWhere('name', $request->input('email'))
            ->first());

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

describe('an account with more than one name', function () {
    beforeEach(function () {
        config(['keyring.limits.per_account' => 3, 'keyring.limits.per_ip' => 100]);

        $this->dana = account('dana@example.com');
        $this->dana->update(['name' => 'dana']);
        account('other@example.com')->update(['name' => 'other']);

        // An email address or a handle, as the recipe has it.
        Keyring::findUsersUsing(fn (Request $request) => User::query()
            ->where('email', $request->string('email')->lower()->value())
            ->orWhere('name', $request->string('email')->lower()->value())
            ->first());
    });

    function guess(string $name, string $password = 'nope'): int
    {
        return test()->postJson('/login', ['email' => $name, 'password' => $password])->status();
    }

    it('answers a name from that name\'s own attempts, whoever else it belongs to', function (string $locked) {
        foreach (range(1, 3) as $attempt) {
            guess($locked);
        }

        expect(guess($locked))->toBe(429);

        // Dana's other name, another account's and nobody's all answer alike,
        // each for as long as a name with no history would.
        $other = $locked === 'dana' ? 'dana@example.com' : 'dana';

        foreach ([$other, 'other@example.com', 'nobody@example.com'] as $name) {
            expect(array_map(fn () => guess($name), range(1, 4)))->toBe([422, 422, 422, 429]);
        }
    })->with(['dana', 'dana@example.com']);

    it('still refuses the account under its other name, without saying so', function () {
        foreach (range(1, 3) as $attempt) {
            guess('dana');
        }

        Event::fake([FactorFailed::class, Lockout::class]);

        $this->postJson('/login', ['email' => 'dana@example.com', 'password' => 'password'])
            ->assertStatus(422)
            ->assertJsonPath('errors.email.0', __('auth.failed'));

        $this->assertGuest();
        Event::assertDispatched(Lockout::class);
        Event::assertNotDispatched(FactorFailed::class);

        $this->travel(61)->seconds();

        $this->postJson('/login', ['email' => 'dana@example.com', 'password' => 'password'])->assertOk();
        $this->assertAuthenticatedAs($this->dana);
    });

    it('never looks at the password of an attempt it refuses quietly, and spends a hash as a check would', function () {
        foreach (range(1, 3) as $attempt) {
            guess('dana');
        }

        Hash::spy();

        guess('dana@example.com', 'password');

        Hash::shouldNotHaveReceived('check');
        Hash::shouldHaveReceived('make')->once();
    });

    it('counts an attempt it refuses quietly against the address', function () {
        config(['keyring.limits.per_ip' => 6]);

        foreach (range(1, 3) as $attempt) {
            guess('dana');
        }

        expect(array_map(fn () => guess('dana@example.com'), range(1, 3)))->toBe([422, 422, 422])
            ->and(guess('other@example.com'))->toBe(429);
    });

    it('shares one count between spellings a finder tells apart and Keyring does not', function (string $email) {
        // Compares what was typed as it came, like the finder in the docs.
        Keyring::findUsersUsing(fn (Request $request) => User::query()->where('email', $request->input('email'))->first());

        foreach (range(1, 3) as $attempt) {
            guess(strtoupper($email));
        }

        expect(guess($email))->toBe(429);
    })->with(['dana@example.com', 'nobody@example.com']);

    it('keeps the owner\'s known browser working under any of the names', function () {
        $device = $this->post('/login', ['email' => 'dana', 'password' => 'password'])->getCookie('keyring_device')->getValue();
        $this->post('/logout');
        $this->flushSession();

        foreach (range(1, 4) as $attempt) {
            $this->withUnencryptedCookies([])->post('/login', ['email' => 'dana', 'password' => 'nope']);
        }

        $this->post('/login', ['email' => 'dana@example.com', 'password' => 'password'])->assertSessionHasErrors('email');
        $this->assertGuest();

        $this->withCookie('keyring_device', $device)
            ->post('/login', ['email' => 'dana@example.com', 'password' => 'password'])
            ->assertRedirect('/dashboard');
    });
});

describe('an account locked out again and again', function () {
    beforeEach(function () {
        config(['keyring.limits.per_account' => 2, 'keyring.limits.per_ip' => 1000, 'keyring.limits.lock_after' => 3]);

        $this->user = account('taylor@example.com');
    });

    /**
     * Guess until the account locks, then wait the lock out.
     */
    function lockOut(int $times, string $email = 'taylor@example.com', string $password = 'nope'): void
    {
        foreach (range(1, $times) as $lockout) {
            test()->post('/login', ['email' => $email, 'password' => $password]);
            test()->post('/login', ['email' => $email, 'password' => $password]);
            test()->travel(2 ** $lockout)->minutes();
        }
    }

    it('lifts each lock by itself until there have been that many in a day', function () {
        lockOut(2);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('then keeps it locked until the password is reset, and says how to get back in', function () {
        Event::fake([AccountLocked::class]);

        lockOut(3);
        $this->travel(7)->days();

        $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertStatus(429)
            ->assertJsonPath('errors.email.0', __('keyring::keyring.locked'));

        $this->assertGuest();
        Event::assertDispatchedTimes(AccountLocked::class, 1);
        Event::assertDispatched(AccountLocked::class, fn (AccountLocked $event) => $event->user->is($this->user) && $event->factor === 'password');

        completeReset($this->user);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase'])->assertRedirect('/dashboard');
    });

    it('tells the owner it is locked and how to unlock it, once the app registers the notice', function () {
        Notification::fake();

        lockOut(3);
        Notification::assertNothingSent();
        completeReset($this->user);

        sendNotifications(['account_locked']);
        $this->travel(2)->days();
        lockOut(3, password: 'not this either');

        $notice = Notification::sent($this->user, AccountLockedNotice::class)->sole();
        $mail = renderedMail($notice->toMail($this->user));

        expect($notice->url)->toBe('http://localhost/forgot-password')
            ->and($notice->ip)->toBe('127.0.0.1')
            ->and($mail['text'])->toContain('Too many failed attempts to sign in have locked your account. Reset your password to unlock it.')
            ->toContain('Reset your password: http://localhost/forgot-password');
    });

    it('leaves the reset link out of the notice when the app has no reset form', function () {
        withFeatures([Features::registration(), Features::securityLog()]);
        Notification::fake();
        sendNotifications(['account_locked']);

        lockOut(3);

        expect(Notification::sent($this->user, AccountLockedNotice::class)->sole()->url)->toBeNull();
    });

    it('sends no notice for a name nobody has', function () {
        Notification::fake();
        sendNotifications(['account_locked']);

        lockOut(3, 'nobody@example.com');

        Notification::assertNothingSent();
    });

    it('logs it against the account', function () {
        lockOut(3);

        expect(SecurityEvent::query()->where('type', 'account_locked')->sole())
            ->authenticatable_id->toBe($this->user->id)
            ->factor->toBe('password');
    });

    it('can be unlocked without a reset', function () {
        lockOut(3);

        Keyring::unlock($this->user);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('answers a name nobody has the same way, and tells nobody', function () {
        Event::fake([AccountLocked::class]);

        lockOut(3, 'nobody@example.com');

        $this->postJson('/login', ['email' => 'nobody@example.com', 'password' => 'nope'])
            ->assertStatus(429)
            ->assertJsonPath('errors.email.0', __('keyring::keyring.locked'));

        Event::assertNotDispatched(AccountLocked::class);
    });

    it('lets the lock go once failures are forgotten', function () {
        lockOut(3);
        $this->travel(31)->days();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('leaves the owner\'s known browser working', function () {
        $device = $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->getCookie('keyring_device')->getValue();
        $this->post('/logout');
        $this->flushSession();

        $this->withUnencryptedCookies([]);
        lockOut(3);

        $this->withCookie('keyring_device', $device)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect('/dashboard');
    });

    it('never holds a second factor, which a reset would not clear', function () {
        $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        foreach (range(1, 4) as $lockout) {
            $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
            $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);
            $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);
            $this->travel(2 ** $lockout)->minutes();
        }

        $this->travel(2)->days();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])->assertRedirect('/dashboard');
    });

    it('does nothing unless the app asks for it', function () {
        config(['keyring.limits.lock_after' => null]);

        lockOut(5);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });
});

describe('the account\'s device cookies in someone else\'s hands', function () {
    beforeEach(function () {
        config(['keyring.limits.per_account' => 100, 'keyring.limits.per_ip' => 1000, 'keyring.limits.consecutive' => 3]);

        $this->user = account('taylor@example.com');
    });

    /**
     * A wrong password from a browser carrying this device cookie, or none.
     */
    function guessWith(?string $device): void
    {
        test()->withCookie('keyring_device', $device ?? 'a browser nobody has seen')
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    }

    it('gives every cookie of the account one allowance between them, not one each', function () {
        $cookies = [deviceCookieFor('taylor@example.com'), deviceCookieFor('taylor@example.com'), deviceCookieFor('taylor@example.com')];

        Hash::spy();

        foreach ([...$cookies, ...$cookies] as $cookie) {
            guessWith($cookie);
        }

        // Three passwords looked at, the cap, however many cookies there are.
        Hash::shouldHaveReceived('check')->times(3);
    });

    it('still keeps the known browsers\' count apart from everyone else\'s', function () {
        $cookie = deviceCookieFor('taylor@example.com');

        foreach (range(1, 4) as $guess) {
            guessWith(null);
        }

        $this->withCookie('keyring_device', $cookie)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect('/dashboard');
    });

    it('treats a cookie from before a password reset as a browser it has never seen', function () {
        $kept = deviceCookieFor('taylor@example.com');

        foreach (range(1, 3) as $guess) {
            guessWith(null);
        }

        $this->travel(5)->seconds();
        completeReset($this->user);

        // The reset started the unknown browsers' count over. The kept
        // cookie counts there too, so it buys nothing more.
        Hash::spy();

        foreach (range(1, 3) as $guess) {
            guessWith(null);
        }

        foreach (range(1, 3) as $guess) {
            guessWith($kept);
        }

        Hash::shouldHaveReceived('check')->times(3);
    });

    it('knows a browser again once it signs in after the reset', function () {
        $cookie = deviceCookieFor('taylor@example.com');

        $this->travel(5)->seconds();
        completeReset($this->user);
        $this->travel(5)->seconds();

        $this->withCookie('keyring_device', $cookie)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase'])
            ->assertRedirect('/dashboard');
        $this->post('/logout');
        $this->flushSession();

        foreach (range(1, 4) as $guess) {
            guessWith(null);
        }

        $this->withCookie('keyring_device', $cookie)
            ->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase'])
            ->assertRedirect('/dashboard');
    });
});

describe('what a reset clears, long after', function () {
    beforeEach(function () {
        config(['keyring.limits.per_account' => 2, 'keyring.limits.per_ip' => 1000, 'keyring.limits.lock_after' => 3]);

        $this->user = account('taylor@example.com');
    });

    it('keeps a lock held however long ago the last reset was', function () {
        completeReset($this->user);

        $this->travel(29)->days();
        lockOut(3);
        $this->travel(2)->days();

        $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase'])->assertStatus(429);
    });

    it('lets the owner in after one reset, however many came before', function () {
        completeReset($this->user);

        $this->travel(29)->days();
        lockOut(3);
        $this->travel(2)->days();

        completeReset($this->user);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a brand new passphrase'])->assertRedirect('/dashboard');
    });
});

it('never holds a security key, which only ever comes second', function () {
    config(['keyring.limits.per_account' => 2, 'keyring.limits.lock_after' => 1]);
    Keyring::factors([Password::class, WebAuthn::securityKeys()]);

    $limits = Keyring::factor('security-key')->limits(Request::create('/login/challenge/security-key', 'POST'), Attempt::start(Purpose::Login, account('taylor@example.com')));

    expect(collect($limits)->whereInstanceOf(AccountLimit::class)->pluck('holdAfter')->filter()->all())->toBe([])
        ->and(collect($limits)->pluck('key')->implode(' '))->not->toContain('|cleared|');
});

it('holds every refusal for the timebox, whichever limit refused it', function () {
    config(['keyring.limits.per_account' => 1, 'keyring.limits.per_ip' => 100]);
    account('taylor@example.com');

    $timebox = new class extends Timebox
    {
        /** @var list<bool> */
        public static array $returnedEarly = [];

        public function call(callable $callback, int $microseconds)
        {
            $result = parent::call($callback, 0);
            self::$returnedEarly[] = $this->earlyReturn;

            return $result;
        }
    };
    $this->app->bind(Timebox::class, $timebox::class);

    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])->assertStatus(422);
    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])->assertStatus(429);
    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertStatus(429);

    expect($timebox::$returnedEarly)->toBe([false, false, false]);
});
