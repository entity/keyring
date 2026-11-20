<?php

declare(strict_types=1);

use Illuminate\Encryption\Encrypter;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Events\Authenticated;
use Keyring\Events\FactorFailed;
use Keyring\Events\RecoveryCodeUsed;
use Keyring\Exceptions\UnregisteredFactor;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\AttemptStore;
use Keyring\Login\Requirement;
use Keyring\Login\SignIn;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Support\EncryptedSession;
use Keyring\Tests\Fixtures\Staff;
use Keyring\Tests\Fixtures\User;

function totpFor(User $user, bool $default = false): Authenticator
{
    return Authenticator::factory()->totp()->for($user, 'authenticatable')->state(['is_default' => $default])->create();
}

it('renders the login page through inertia', function () {
    $this->inertia()->get('/login')
        ->assertOk()
        ->assertJsonPath('component', 'auth/login')
        ->assertJsonPath('props.canRegister', true)
        ->assertJsonPath('props.canResetPassword', true);
});

it('answers like an unknown user when the finder returns someone the guard would not load back', function () {
    taylor();
    $staff = staff();
    Keyring::findUsersUsing(fn () => $staff);

    $this->post('/login', ['email' => 'staff@example.com', 'password' => 'password'])
        ->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
});

it('drops a sign in that started under another guard', function () {
    taylor();
    $totp = Authenticator::factory()->totp()->for(staff(), 'authenticatable')->create();
    config([
        'auth.providers.staff' => ['driver' => 'eloquent', 'model' => Staff::class],
        'auth.guards.staff' => ['driver' => 'session', 'provider' => 'staff'],
        'keyring.guard' => 'staff',
    ]);

    $this->post('/login', ['email' => 'staff@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    config(['keyring.guard' => 'web']);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect('/login')
        ->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);

    $this->assertGuest('web');
    expect($totp->fresh()->last_used_at)->toBeNull();
});

it('refuses to log in anyone the guard would not load back', function () {
    taylor();
    $staff = staff();

    expect(fn () => app(SignIn::class)->as(request(), $staff, []))
        ->toThrow(ValidationException::class, __('auth.failed'));

    $this->assertGuest('web');
});

it('signs in with just a password when nothing else is enrolled', function () {
    Event::fake([Authenticated::class]);
    $user = taylor();

    $this->post('/login', ['email' => 'Taylor@Example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
    Event::assertDispatched(Authenticated::class);
});

it('gives the same error for a wrong password and an unknown account', function () {
    Event::fake([FactorFailed::class]);
    taylor();

    $wrong = $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope'])
        ->assertSessionHasErrors('email')->getSession()->get('errors')->first('email');

    $unknown = $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'nope'])
        ->assertSessionHasErrors('email')->getSession()->get('errors')->first('email');

    expect($wrong)->toBe($unknown)->toBe(__('auth.failed'));
    $this->assertGuest();
    Event::assertDispatchedTimes(FactorFailed::class, 2);
});

// The timebox only pads a refusal up to its length, so the two have to cost
// the same underneath it, in a process that lives for one request too.
it('hashes once for a wrong password and once for an unknown account', function () {
    taylor();

    $hasher = new class extends BcryptHasher
    {
        /** @var list<string> */
        public array $calls = [];

        public function make(#[SensitiveParameter] $value, array $options = [])
        {
            $this->calls[] = 'make';

            return parent::make($value, $options);
        }

        public function check(#[SensitiveParameter] $value, $hashedValue, array $options = [])
        {
            $this->calls[] = 'check';

            return parent::check($value, $hashedValue, $options);
        }
    };

    Hash::extend('counting', fn () => $hasher);
    config(['hashing.driver' => 'counting']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    expect($hasher->calls)->toBe(['check']);

    $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'nope']);
    expect($hasher->calls)->toBe(['check', 'make', 'make']);
});

it('asks for a second factor when one is enrolled', function () {
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->assertGuest();

    $this->inertia()->get(route('keyring.login.challenge'))
        ->assertOk()
        ->assertJsonPath('component', 'auth/challenge')
        ->assertJsonPath('props.factor', 'totp')
        ->assertJsonPath('props.authenticator.id', $totp->id);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
});

it('rejects a wrong code and keeps the user signed out', function () {
    $user = taylor();
    totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000'])
        ->assertSessionHasErrors(['code' => __('keyring::keyring.invalid')]);

    $this->assertGuest();
});

it('lets the app keep its own referer, and keeps it from other sites', function () {
    // A page in a single-page app keeps the policy of the page it loaded on:
    // none at all would strip the referer from every request after signing in.
    $this->get('/login')->assertHeader('Referrer-Policy', 'same-origin');
});

// The page an emailed link opens sends no Referer at all, and an Inertia app
// would go on running in it: every page after would send none either.
describe('leaving the page an emailed link opened', function () {
    beforeEach(function () {
        $this->user = taylor();
        $this->token = app('auth.password')->broker()->createToken($this->user);
        $this->page = route('password.reset', ['token' => $this->token, 'email' => 'taylor@example.com']);

        $this->inertia()->get($this->page)->assertOk()->assertHeader('Referrer-Policy', 'no-referrer');
    });

    it('has an Inertia app load the next page in full, with what was flashed for it', function () {
        $this->inertia()->post(route('password.update'), ['token' => $this->token, 'email' => 'taylor@example.com', 'password' => 'a-long-new-password', 'password_confirmation' => 'a-long-new-password'])
            ->assertStatus(409)
            ->assertHeader('X-Inertia-Location', route('login'))
            ->assertHeaderMissing('Location')
            ->assertSessionHas('status', 'password-reset');

        $this->flushHeaders()->get('/login')->assertHeader('Referrer-Policy', 'same-origin');
    });

    it('sends a form that failed back to the page it is on', function () {
        $this->inertia()->post(route('password.update'), ['token' => $this->token, 'email' => 'taylor@example.com', 'password' => 'short', 'password_confirmation' => 'short'])
            ->assertRedirect($this->page)
            ->assertHeaderMissing('X-Inertia-Location')
            ->assertSessionHasErrors('password');
    });

    it('redirects a browser that is not running Inertia as it always did', function () {
        $this->flushHeaders()->post(route('password.update'), ['token' => $this->token, 'email' => 'taylor@example.com', 'password' => 'a-long-new-password', 'password_confirmation' => 'a-long-new-password'])
            ->assertRedirect(route('login'))
            ->assertHeaderMissing('X-Inertia-Location');
    });

    it('leaves an Inertia redirect from any other form alone', function () {
        $this->inertia()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertRedirect('/dashboard')
            ->assertHeaderMissing('X-Inertia-Location');
    });
});

it('sends a failed form back to its own page, though the browser sends no referer', function () {
    totpFor(taylor());

    // The last page loaded in full, which is what Laravel remembers.
    $this->get('/login');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    // An Inertia visit, which Laravel doesn't.
    $this->inertia()->withHeaders(['X-Requested-With' => 'XMLHttpRequest'])->get('/login/challenge/totp')->assertOk();

    $this->flushHeaders()->post('/login/challenge/totp', ['code' => '000000'])
        ->assertRedirect('/login/challenge/totp')
        ->assertSessionHasErrors('code');
});

it('does not take a prefetched page for the one the user is on', function () {
    taylor();
    $this->get('/login');

    $this->inertia()->withHeaders(['X-Requested-With' => 'XMLHttpRequest', 'Purpose' => 'prefetch'])->get('/register')->assertOk();

    $this->flushHeaders()->post('/login', ['email' => 'taylor@example.com'])->assertRedirect('/login');
});

it('answers a username that is not text with a validation error', function () {
    taylor();

    $this->postJson('/login', ['email' => ['taylor@example.com'], 'password' => 'password'])
        ->assertJsonValidationErrors('email');
    $this->assertGuest();
});

it('takes a totp code from one step either side of now, and none from further off', function (int $step, bool $accepted) {
    $totp = totpFor(taylor());

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret, $step)]);

    $accepted ? $this->assertAuthenticated() : $this->assertGuest();
})->with([
    'two steps back' => [-2, false],
    'the step before' => [-1, true],
    'this step' => [0, true],
    'the step after' => [1, true],
    'two steps on' => [2, false],
]);

it('takes only this step\'s totp code with a window of zero, as asvs 6.5.5 asks', function (int $step, bool $accepted) {
    Keyring::factors([Password::class, fn ($app) => $app->make(Totp::class, ['window' => 0])]);
    $totp = totpFor(taylor());

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret, $step)]);

    $accepted ? $this->assertAuthenticated() : $this->assertGuest();
})->with([
    'the step before' => [-1, false],
    'this step' => [0, true],
    'the step after' => [1, false],
]);

it('refuses a totp window wider than one step either side', function (int $window) {
    Keyring::factors([Password::class, fn ($app) => $app->make(Totp::class, ['window' => $window])]);

    expect(fn () => Keyring::registered())->toThrow(LogicException::class, "The [totp] factor was given a window of {$window}. Keyring accepts 0");
})->with([2, 20, -1]);

it('does not accept the same totp code twice', function () {
    $user = taylor();
    $totp = totpFor($user);
    $code = totpCode($totp->secret);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => $code])->assertRedirect('/dashboard');

    $this->post('/logout');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => $code])->assertSessionHasErrors('code');

    $this->assertGuest();
});

it('offers other ways to sign in', function () {
    $user = taylor();
    $first = totpFor($user, default: true);
    $second = totpFor($user);
    Authenticator::factory()->recoveryCodes()->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $response = $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.authenticator.id', $first->id);

    expect(collect($response->json('props.alternatives'))->pluck('factor')->all())->toBe(['totp', 'recovery'])
        ->and($response->json('props.alternatives.0.id'))->toBe($second->id)
        ->and($response->json('props.alternatives.1.remaining'))->toBe(3);

    $this->inertia()->get(route('keyring.login.challenge', ['recovery']))
        ->assertJsonPath('props.factor', 'recovery');
});

it('goes back to the challenge page when asked for a sign-in method the user doesn\'t have', function () {
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $this->get(route('keyring.login.challenge', ['passkey']))->assertRedirect(route('keyring.login.challenge'));

    $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.authenticator.id', $totp->id);
    $this->assertGuest();
});

it('signs in with a recovery code once', function () {
    Event::fake([RecoveryCodeUsed::class]);
    $user = taylor();
    totpFor($user);
    Authenticator::factory()->recoveryCodes()->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge', ['recovery']));
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'AAAA AAAA AAAA AAAA AAAA AAAA AA'])->assertRedirect('/dashboard');

    Event::assertDispatched(RecoveryCodeUsed::class, fn ($event) => $event->remaining === 2);

    $this->post('/logout');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge', ['recovery']));
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertSessionHasErrors('code');
});

it('signs in with the last recovery code', function () {
    $user = taylor();
    totpFor($user);
    Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge', ['recovery']));
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
});

it('locks out after too many failures', function () {
    config(['keyring.limits.per_account' => 2]);
    taylor();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertStatus(302)
        ->assertSessionHasErrors('email');

    $this->assertGuest();
});

it('uses the policy to decide what is needed', function () {
    Keyring::require(fn (User $user) => $user->email === 'admin@example.com'
        ? Requirement::aal2()->including(Category::Possession)
        : Requirement::aal1());

    $admin = taylor(['email' => 'admin@example.com']);
    totpFor($admin);

    $this->post('/login', ['email' => 'admin@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $user = taylor(['email' => 'user@example.com']);
    totpFor($user);

    $this->post('/login', ['email' => 'user@example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');
});

it('turns users away when the policy needs factors they do not have', function () {
    Keyring::require(Requirement::aal2());
    taylor();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->get(route('keyring.login.challenge'))
        ->assertRedirect('/login')
        ->assertSessionHasErrors(['email' => __('keyring::keyring.unavailable')]);
});

it('asks for the enrolled second factor when the policy wants more than the user can give', function (Requirement $policy) {
    Keyring::require($policy);
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->assertGuest();

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2);
})->with([
    'phishing resistant' => fn () => Requirement::aal2()->phishingResistant()->ifEnrolled(),
    'aal3' => fn () => Requirement::aal3()->ifEnrolled(),
    'three factors' => fn () => Requirement::factors(3)->ifEnrolled(),
    'a category they lack' => fn () => Requirement::aal2()->including(Category::Inherence)->ifEnrolled(),
    'one phishing resistant factor' => fn () => Requirement::aal1()->phishingResistant()->ifEnrolled(),
]);

it('signs in with just a password under a stricter policy when there is no real second factor', function (?array $codes) {
    Keyring::require(Requirement::aal2()->phishingResistant()->ifEnrolled());
    $user = taylor();

    if ($codes !== null) {
        Authenticator::factory()->recoveryCodes($codes)->for($user, 'authenticatable')->create();
    }

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);
})->with([
    'only a password' => [null],
    'a used-up recovery set' => [[]],
    'only recovery codes' => [['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa']],
]);

it('still accepts a recovery code when the policy is out of reach', function () {
    Keyring::require(Requirement::aal2()->phishingResistant()->ifEnrolled());
    $user = taylor();
    totpFor($user);
    Authenticator::factory()->recoveryCodes()->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->get(route('keyring.login.challenge', ['recovery']));
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
});

it('does not offer a used-up recovery set under no downgrade', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys(), Totp::class, RecoveryCodes::class]);
    Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
    $user = taylor();
    Authenticator::factory()->securityKey()->for($user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes([])->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.factor', 'security-key')
        ->assertJsonPath('props.alternatives', []);
});

it('does not offer a used-up recovery set under a one-factor no downgrade', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys(), Totp::class, RecoveryCodes::class]);
    Keyring::require(Requirement::aal1()->noDowngrade());
    $user = taylor();
    Authenticator::factory()->securityKey()->for($user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes([])->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.factor', 'security-key')
        ->assertJsonPath('props.alternatives', []);
});

it('keeps no-downgrade when the rest of the policy is out of reach', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys(), Totp::class, RecoveryCodes::class]);
    Keyring::require(Requirement::factors(3)->ifEnrolled()->noDowngrade());
    $user = taylor();
    Authenticator::factory()->securityKey()->for($user, 'authenticatable')->create();
    totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.factor', 'security-key')
        ->assertJsonPath('props.alternatives', []);
});

it('sends people back to login when the attempt has expired', function () {
    $user = taylor();
    totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->travel(11)->minutes();

    $this->get(route('keyring.login.challenge'))->assertRedirect('/login');
});

it('starts over when the half-finished sign in in the session can\'t be read back', function (array $broken) {
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    // As a release that kept it differently, or a session that was tampered
    // with, might have left it.
    $session = app(EncryptedSession::class);
    $session->put(AttemptStore::key(Purpose::Login), [...$session->get(AttemptStore::key(Purpose::Login)), ...$broken]);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);

    $this->assertGuest();
    expect(session()->has(AttemptStore::key(Purpose::Login)))->toBeFalse();
})->with([
    'a purpose it doesn\'t know' => [['purpose' => 'unlock']],
    'a field of the wrong type' => [['verifications' => 'password']],
]);

it('starts over when the half-finished sign in was kept under another app key, or isn\'t keyring\'s', function (string $payload) {
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    session()->put(AttemptStore::key(Purpose::Login), $payload);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);

    $this->assertGuest();
})->with([
    'another app key' => fn () => new Encrypter(random_bytes(32), 'aes-256-cbc')->encryptString('{"id":"x"}'),
    'encrypted, but not json' => fn () => Crypt::encryptString('not json'),
    'encrypted json that isn\'t a sign in' => fn () => Crypt::encryptString('"a string"'),
]);

it('ends a half-finished sign in when the account is deleted meanwhile', function () {
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $user->delete();

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors(['email' => __('keyring::keyring.expired')]);

    $this->assertGuest();
});

it('answers json clients with json', function () {
    $user = taylor();
    totpFor($user);

    $this->postJson('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertStatus(202)
        ->assertJson(['status' => 'challenge']);
});

it('signs out', function () {
    $user = taylor();

    $this->actingAs($user)->post('/logout')->assertRedirect('/');

    $this->assertGuest();
});

it('ends a half-finished sign in when the password changes meanwhile', function () {
    $user = taylor();
    $totp = totpFor($user);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    // The owner resets their password somewhere else.
    Keyring::withoutProtection(fn () => $user->update(['password' => 'a brand new passphrase']));

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect(route('login'))
        ->assertSessionHasErrors('email');
    $this->assertGuest();
});

it('signs in when checking the password rehashes it', function () {
    $user = taylor();
    Hash::driver('bcrypt')->setRounds(5);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');

    expect(password_get_info($user->fresh()->password)['options']['cost'])->toBe(5);
    $this->assertAuthenticatedAs($user);
});

it('keeps a half-finished sign in when checking the password rehashes it', function () {
    $user = taylor();
    $totp = totpFor($user);
    Hash::driver('bcrypt')->setRounds(5);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));
    expect(password_get_info($user->fresh()->password)['options']['cost'])->toBe(5);

    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret)])
        ->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user);
});

it('finds users the app\'s way, and answers the same when it finds no one', function () {
    $user = taylor(['name' => 'taylor']);
    Keyring::findUsersUsing(fn ($request) => User::query()
        ->where('email', $request->input('email'))
        ->orWhere('name', $request->input('email'))
        ->first());

    $this->post('/login', ['email' => 'taylor', 'password' => 'password'])->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($user);
    $this->post('/logout');

    Keyring::findUsersUsing(fn () => null);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertSessionHasErrors(['email' => __('auth.failed')]);
    $this->assertGuest();
});

it('normalises usernames the app\'s way', function () {
    // Staff sign in with just their name; it's completed to their address.
    Keyring::normalizeUsernamesUsing(fn (string $username) => Str::lower(trim($username)).(str_contains($username, '@') ? '' : '@example.com'));
    taylor();

    $this->post('/login', ['email' => ' Taylor ', 'password' => 'password'])->assertRedirect('/dashboard');
});

describe('authenticators for a factor that isn\'t registered', function () {
    beforeEach(function () {
        Exceptions::fake();
        $this->user = taylor();
        totpFor($this->user);
        Keyring::factors([Password::class]);
    });

    it('refuses the sign in rather than skip them, and says why in the log', function () {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
            ->assertSessionHasErrors(['email' => __('keyring::keyring.unavailable')]);

        $this->assertGuest();
        expect(session()->has('keyring.attempt.login'))->toBeFalse();
        Exceptions::assertReported(fn (UnregisteredFactor $e) => str_contains($e->getMessage(), '[totp]'));
    });

    it('refuses step-up too', function () {
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subDay());
        $this->get(route('keyring.confirm.challenge', 'password'));

        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password'])
            ->assertSessionHasErrors(['password' => __('keyring::keyring.unavailable')]);
    });
});
