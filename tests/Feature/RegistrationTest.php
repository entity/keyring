<?php

declare(strict_types=1);

use App\Actions\Keyring\CreateNewUser;
use App\Notifications\Keyring\AlreadyRegistered;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Auth\Notifications\VerifyEmail;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Foundation\Http\Events\RequestHandled;
use Illuminate\Notifications\AnonymousNotifiable;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Timebox;
use Illuminate\Testing\TestResponse;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Exceptions\EmailVerificationRequired;
use Keyring\Exceptions\MissingNotification;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\KeyringServiceProvider;
use Keyring\Login\Registration;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Sessions\SessionAssurance;
use Keyring\Tests\Fixtures\PlainUser;
use Keyring\Tests\Fixtures\RacedRegistration;
use Keyring\Tests\Fixtures\Staff;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    Notification::fake();
});

afterEach(fn () => Model::clearBootedModels());

/**
 * The registration form, filled in well unless a field says otherwise.
 *
 * @param  array<string, mixed>  $fields
 * @return array<string, mixed>
 */
function registrationForm(array $fields = []): array
{
    return [
        'name' => 'Taylor',
        'email' => 'taylor@example.com',
        'password' => 'correct horse battery staple',
        'password_confirmation' => 'correct horse battery staple',
        ...$fields,
    ];
}

/**
 * Addresses a new account can't have, and one it can. Each sets up its case
 * and returns the address to register with.
 *
 * @return array<string, Closure(): string>
 */
function addressesToRegister(): array
{
    return [
        'free' => fn () => 'free@example.com',
        'taken' => fn () => taylor(['email' => 'taken@example.com'])->email,
        'taken, and never verified' => fn () => taylor(['email' => 'pending@example.com', 'email_verified_at' => null])->email,
        'reserved for its previous owner' => function () {
            // Their email change has applied, and can still be undone.
            $change = new PendingChange([
                'attribute' => 'email',
                'value' => 'moved@example.com',
                'previous_value' => 'reserved@example.com',
                'confirm_token' => PendingChange::hashToken('confirm'),
                'revert_token' => PendingChange::hashToken('revert'),
                'expires_at' => now()->addDay(),
                'applied_at' => now(),
                'revertable_until' => now()->addDay(),
            ]);
            $change->authenticatable()->associate(taylor(['email' => 'moved@example.com']))->save();

            return 'reserved@example.com';
        },
        'an account the app keeps out' => function () {
            Keyring::allowSignInWhen(fn (User $user) => $user->name !== 'Banned');

            return taylor(['name' => 'Banned', 'email' => 'banned@example.com'])->email;
        },
        'an account a global scope hides' => function () {
            $address = taylor(['name' => 'Hidden', 'email' => 'hidden@example.com'])->email;
            User::addGlobalScope('hidden', fn (Builder $query) => $query->where('name', '!=', 'Hidden'));

            return $address;
        },
    ];
}

/**
 * Everything a visitor can see of an answer: its status, headers, body and
 * cookies, what it left in their session, and whether it signed them in.
 *
 * @return array<string, mixed>
 */
function visibleAnswer(TestResponse $response): array
{
    return [
        'status' => $response->getStatusCode(),
        'headers' => Arr::except($response->headers->all(), ['date', 'set-cookie']),
        'body' => $response->getContent(),
        'cookies' => collect($response->headers->getCookies())->map->getName()->sort()->values()->all(),
        'session' => Arr::except(session()->all(), ['_token', '_old_input', 'errors']),
        'errors' => test()->sessionErrors()->toArray(),
        'guest' => auth()->guest(),
    ];
}

/**
 * The link in the verification email a user was sent.
 */
function verificationLinkSentTo(User $user): string
{
    $url = null;

    Notification::assertSentTo($user, VerifyEmail::class, function (VerifyEmail $notification) use ($user, &$url) {
        $url = $notification->toMail($user)->actionUrl;

        return true;
    });

    return parse_url($url, PHP_URL_PATH).'?'.parse_url($url, PHP_URL_QUERY);
}

it('renders the register page', function () {
    $this->inertia()->get('/register')->assertJsonPath('component', 'auth/register');
});

it('can turn registration off', function () {
    withFeatures(array_values(array_diff(Features::all(), [Features::registration()])));

    expect(Route::has('register'))->toBeFalse()
        ->and(Route::has('login'))->toBeTrue();
});

it('uses the owasp password rules', function () {
    $this->post('/register', registrationForm(['password' => 'password', 'password_confirmation' => 'password']))
        ->assertSessionHasErrors('password');
});

// As Keyring ships: registering gives away nothing about who has an account.
describe('hiding who has an account', function () {
    it('answers the same for an address that is free, taken, reserved or kept out', function (bool $json) {
        $answers = [];

        foreach (addressesToRegister() as $case => $address) {
            // A new visitor each time, with the form limit starting over.
            $this->flushSession();
            $this->travel(2)->minutes();

            $form = registrationForm(['email' => $address()]);

            $answers[$case] = visibleAnswer($json ? $this->postJson('/register', $form) : $this->post('/register', $form));
        }

        expect($answers['free']['status'])->toBe($json ? 200 : 302)
            ->and($answers['free']['guest'])->toBeTrue()
            ->and($answers['free']['errors'])->toBe([]);

        foreach ($answers as $case => $answer) {
            expect($answer)->toEqual($answers['free'], "A {$case} address was answered differently.");
        }
    })->with(['a form post' => false, 'json' => true]);

    it('says to check the inbox, whatever happened', function () {
        $this->post('/register', registrationForm())
            ->assertRedirect(route('login'))
            ->assertSessionHas('status', 'registration-received');

        $this->inertia()->get('/login')->assertJsonPath('props.status', __('keyring::status.registration-received'));
    });

    it('says so as json too', function () {
        $this->postJson('/register', registrationForm())
            ->assertOk()
            ->assertExactJson([
                'status' => 'registration-received',
                'message' => __('keyring::status.registration-received'),
                'redirect' => route('login'),
            ]);
    });

    it('shows every other validation error, the same for each address', function () {
        $answers = [];

        foreach (addressesToRegister() as $case => $address) {
            $this->flushSession();
            $this->travel(2)->minutes();

            $answers[$case] = visibleAnswer($this->post('/register', registrationForm([
                'name' => '',
                'email' => $address(),
                'password' => 'password',
                'password_confirmation' => 'password',
            ])));
        }

        expect(array_keys($answers['free']['errors']))->toBe(['name', 'password']);

        foreach ($answers as $case => $answer) {
            expect($answer)->toEqual($answers['free'], "A {$case} address was answered differently.");
        }

        Notification::assertNothingSent();
        expect(User::query()->withoutGlobalScopes()->where('email', 'free@example.com')->exists())->toBeFalse();
    });

    it('creates a new user, leaves them signed out and emails them a verification link', function () {
        // An app's own answer to who is signed in doesn't apply: nobody is.
        Keyring::signInAfterRegistering(true);

        $this->post('/register', registrationForm(['email' => 'Taylor@Example.com']))->assertRedirect(route('login'));

        $user = User::sole();

        $this->assertGuest();
        Notification::assertSentToTimes($user, VerifyEmail::class, 1);
        Notification::assertNotSentTo(new AnonymousNotifiable, AlreadyRegistered::class);

        expect($user->email)->toBe('taylor@example.com')
            ->and($user->hasVerifiedEmail())->toBeFalse()
            ->and(Hash::check('correct horse battery staple', $user->password))->toBeTrue()
            ->and(app(SessionRegistry::class)->forUser($user))->toBeEmpty();
    });

    it('creates nothing for a taken address, and tells it once that someone tried', function () {
        $owner = taylor();

        $this->post('/register', registrationForm(['name' => 'Someone Else', 'email' => ' TAYLOR@example.com ']));

        $this->assertGuest();
        Notification::assertSentOnDemandTimes(AlreadyRegistered::class, 1);
        Notification::assertSentOnDemand(AlreadyRegistered::class, fn (AlreadyRegistered $notice, array $channels, AnonymousNotifiable $to) => $to->routes['mail'] === 'taylor@example.com'
            && $notice->loginUrl === route('login')
            && $notice->resetUrl === route('password.request'));
        Notification::assertNothingSentTo($owner);

        expect(User::count())->toBe(1)
            ->and($owner->fresh()->only('name', 'password'))->toBe($owner->only('name', 'password'));
    });

    it('builds the links in that email from APP_URL, and leaves out a reset link the app has no page for', function () {
        config(['app.url' => 'https://app.example.com']);
        withFeatures(array_values(array_diff(Features::all(), [Features::resetPasswords()])));
        taylor();

        $this->withServerVariables(['HTTP_HOST' => 'evil.test'])->post('/register', registrationForm());

        Notification::assertSentOnDemand(AlreadyRegistered::class, fn (AlreadyRegistered $notice) => $notice->loginUrl === 'https://app.example.com/login' && $notice->resetUrl === null);
    });

    it('tells an address held for its previous owner, or whose account can\'t sign in, the same way', function (string $case) {
        $address = addressesToRegister()[$case]();
        $users = User::query()->withoutGlobalScopes()->count();

        $this->post('/register', registrationForm(['email' => $address]));

        Notification::assertSentOnDemand(AlreadyRegistered::class, fn (AlreadyRegistered $notice, array $channels, AnonymousNotifiable $to) => $to->routes['mail'] === $address);
        expect(User::query()->withoutGlobalScopes()->count())->toBe($users);
    })->with(['reserved for its previous owner', 'an account the app keeps out', 'an account a global scope hides']);

    it('sends an account that never verified another link, since the first may be lost', function () {
        $pending = taylor(['email_verified_at' => null]);

        $this->post('/register', registrationForm(['password' => 'someone else\'s long password', 'password_confirmation' => 'someone else\'s long password']));

        Notification::assertSentToTimes($pending, VerifyEmail::class, 1);
        Notification::assertNotSentTo(new AnonymousNotifiable, AlreadyRegistered::class);

        // Whoever registered first keeps the password they chose.
        expect(User::count())->toBe(1)
            ->and(Hash::check('password', $pending->fresh()->password))->toBeTrue();
    });

    it('mails a taken address five times an hour at most, without saying so', function () {
        taylor();
        $answers = [];

        foreach (range(1, 7) as $try) {
            $this->flushSession();
            $this->travel(2)->minutes();

            $answers[] = visibleAnswer($this->post('/register', registrationForm()));
        }

        Notification::assertSentOnDemandTimes(AlreadyRegistered::class, 5);
        expect(array_unique($answers, SORT_REGULAR))->toHaveCount(1);

        $this->travel(61)->minutes();
        $this->post('/register', registrationForm());

        Notification::assertSentOnDemandTimes(AlreadyRegistered::class, 6);
    });

    it('counts the first verification link against what a new address can be sent', function () {
        foreach (range(1, 7) as $try) {
            $this->flushSession();
            $this->travel(2)->minutes();

            $this->post('/register', registrationForm());
        }

        Notification::assertSentToTimes(User::sole(), VerifyEmail::class, 5);
    });

    it('keeps the form limit of six a minute', function () {
        foreach (range(1, 6) as $try) {
            $this->post('/register', registrationForm(['email' => "user{$try}@example.com"]))->assertRedirect();
        }

        $this->post('/register', registrationForm(['email' => 'user7@example.com']))->assertStatus(429);

        expect(User::count())->toBe(6);
    });

    it('mails nobody until the response has gone, so how long mail takes says nothing', function (Closure $setUp, string $notification) {
        $setUp();
        $sentBeforeAnswering = null;

        Event::listen(RequestHandled::class, function () use (&$sentBeforeAnswering) {
            $sentBeforeAnswering = Notification::sentNotifications();
        });

        $this->post('/register', registrationForm());

        expect($sentBeforeAnswering)->toBe([]);
        Notification::assertSentTimes($notification, 1);
    })->with([
        'a free address' => [fn () => null, VerifyEmail::class],
        'a taken address' => [fn () => taylor(), AlreadyRegistered::class],
    ]);

    it('dispatches Registered for a new user only, after the response', function () {
        Event::fake([Registered::class]);
        taylor(['email' => 'taken@example.com']);

        $this->post('/register', registrationForm(['email' => 'taken@example.com']));
        Event::assertNotDispatched(Registered::class);

        $this->post('/register', registrationForm());
        Event::assertDispatchedTimes(Registered::class, 1);
    });

    it('hashes one password whether or not the address is free', function (Closure $setUp) {
        $setUp();
        Hash::spy();

        $this->post('/register', registrationForm());

        Hash::shouldHaveReceived('make')->once();
    })->with(addressesToRegister());

    it('takes the timebox for a free address, a taken one and a refused form alike', function (Closure $setUp, array $fields) {
        $setUp();
        config(['keyring.timebox' => '400ms']);

        $timebox = new class extends Timebox
        {
            /** @var list<int> */
            public array $waited = [];

            protected function usleep(int $microseconds): void
            {
                $this->waited[] = $microseconds;
            }
        };
        app()->instance(Timebox::class, $timebox);

        $this->post('/register', registrationForm($fields));

        // One wait, for what was left of the 400ms, and no leaving early.
        expect($timebox->waited)->toHaveCount(1)
            ->and($timebox->waited[0])->toBeGreaterThan(0)->toBeLessThanOrEqual(400_000)
            ->and($timebox->earlyReturn)->toBeFalse();
    })->with([
        'a free address' => [fn () => null, []],
        'a taken address' => [fn () => taylor(), []],
        'a refused form' => [fn () => null, ['password' => 'short', 'password_confirmation' => 'short']],
    ]);

    it('answers the same when another request took the address a moment before', function () {
        app()->bind(Registration::class, RacedRegistration::class);
        $owner = taylor();

        $this->post('/register', registrationForm())
            ->assertRedirect(route('login'))
            ->assertSessionHas('status', 'registration-received');

        // The insert the unique index refused left the database usable.
        Notification::assertSentOnDemandTimes(AlreadyRegistered::class, 1);
        expect(User::sole()->is($owner))->toBeTrue();
    });

    it('still fails when the users table refuses a new user for another reason', function () {
        // A unique index on something else, which the action let through.
        Keyring::createUsersUsing((new class extends CreateNewUser
        {
            public function create(array $input): User
            {
                throw new UniqueConstraintViolationException('testing', 'insert into users', [], new Exception('users_handle_unique'));
            }
        })::class);

        $this->withoutExceptionHandling();

        expect(fn () => $this->post('/register', registrationForm()))->toThrow(UniqueConstraintViolationException::class);
    });

    it('refuses the password alone until the address is verified, like an account that isn\'t there', function () {
        $this->post('/register', registrationForm());

        Hash::spy();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])
            ->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
        Hash::shouldNotHaveReceived('check');
        Hash::shouldHaveReceived('make')->once();
    });

    it('lets a new user verify by following the link and signing in, and sign in from then on', function () {
        Event::fake([Verified::class]);

        $this->post('/register', registrationForm());
        $user = User::sole();
        $link = verificationLinkSentTo($user);

        // The link alone verifies nothing: it sends the browser to sign in.
        $this->flushSession();
        $this->get($link)->assertRedirect(route('login'))->assertSessionHas('status', 'sign-in-to-verify');

        expect($user->fresh()->hasVerifiedEmail())->toBeFalse();
        $this->assertGuest();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])
            ->assertRedirect(url($link));

        $this->assertAuthenticatedAs($user);
        Event::assertDispatchedTimes(Verified::class, 1);
        expect($user->fresh()->hasVerifiedEmail())->toBeTrue()
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1);

        $this->get($link)->assertRedirect('/dashboard?verified=1');
        Event::assertDispatchedTimes(Verified::class, 1);

        // And like anyone else afterwards, from any browser.
        $this->post('/logout');
        $this->flushSession();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($user);
    });

    it('shows the login page why it was sent there from the link', function () {
        $this->post('/register', registrationForm());
        $link = verificationLinkSentTo(User::sole());

        $this->flushSession();
        $this->get($link);

        $this->inertia()->get('/login')->assertJsonPath('props.status', __('keyring::status.sign-in-to-verify'));
    });

    it('does not verify an address for whoever holds the link but not the password', function () {
        // Someone registers an address that isn't theirs. Its owner gets the email.
        $this->post('/register', registrationForm());
        $user = User::sole();

        $this->flushSession();
        $this->get(verificationLinkSentTo($user));

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'the owner never chose a password'])
            ->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
        expect($user->fresh()->hasVerifiedEmail())->toBeFalse();
    });

    it('only lets the link\'s own account sign in from the browser that followed it', function () {
        $this->post('/register', registrationForm());
        $this->travel(2)->minutes();
        $this->post('/register', registrationForm(['email' => 'abigail@example.com']));

        $taylor = User::query()->where('email', 'taylor@example.com')->sole();

        $this->flushSession();
        $this->get(verificationLinkSentTo($taylor));

        $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'correct horse battery staple'])
            ->assertSessionHasErrors(['email' => __('auth.failed')]);

        $this->assertGuest();
    });

    it('stops accepting a followed link once it has expired, or the address has changed', function (Closure $change) {
        $this->post('/register', registrationForm());
        $user = User::sole();

        $this->flushSession();
        $this->get(verificationLinkSentTo($user));

        $change($user);

        $this->post('/login', ['email' => $user->fresh()->email, 'password' => 'correct horse battery staple'])
            ->assertSessionHasErrors(['email' => __('auth.failed')]);

        expect($user->fresh()->hasVerifiedEmail())->toBeFalse();
    })->with([
        'expired' => fn () => test()->travel(61)->minutes(),
        'another address' => fn (User $user) => Keyring::withoutProtection(fn () => $user->forceFill(['email' => 'other@example.com'])->save()),
    ]);

    it('refuses a link whose signature is wrong before keeping anything', function () {
        $this->post('/register', registrationForm());
        $user = User::sole();

        $this->flushSession();
        $this->get(verificationLinkSentTo($user).'tampered')->assertForbidden();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'correct horse battery staple'])
            ->assertSessionHasErrors(['email' => __('auth.failed')]);
    });

    it('takes a finished password reset as proof of the address too', function () {
        Event::fake([Verified::class]);

        // Someone else registered the owner's address first, with a password of their own.
        $this->post('/register', registrationForm(['password' => 'a squatter\'s long password', 'password_confirmation' => 'a squatter\'s long password']));
        $user = User::sole();

        $this->post('/forgot-password', ['email' => 'taylor@example.com']);

        $token = null;
        Notification::assertSentTo($user, ResetPassword::class, function (ResetPassword $notice) use (&$token) {
            $token = $notice->token;

            return true;
        });

        $this->post('/reset-password', [
            'token' => $token,
            'email' => 'taylor@example.com',
            'password' => 'the owner\'s own long passphrase',
            'password_confirmation' => 'the owner\'s own long passphrase',
        ])->assertSessionHasNoErrors();

        Event::assertDispatchedTimes(Verified::class, 1);
        expect($user->fresh()->hasVerifiedEmail())->toBeTrue();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'a squatter\'s long password'])->assertSessionHasErrors('email');
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'the owner\'s own long passphrase'])->assertRedirect('/dashboard');
    });

    it('signs out a session whose account is no longer verified', function () {
        Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
        $user = taylor();

        $this->actingAs($user)->get('/home')->assertOk();

        $user->forceFill(['email_verified_at' => null])->save();
        auth()->forgetGuards();

        $this->get('/home')->assertRedirect('/login');
    });

    it('never signs a new user in, for a registration flow of the app\'s own that asks', function () {
        Keyring::signInAfterRegistering(true);

        expect(Keyring::hidesRegisteredAddresses())->toBeTrue()
            ->and(Keyring::signsInAfterRegistering(taylor(), request()))->toBeFalse();
    });

    describe('without what it needs', function () {
        it('stops the app booting when email verification is off', function () {
            config(['keyring.features' => [Features::registration(), Features::resetPasswords()]]);

            expect(fn () => new KeyringServiceProvider($this->app)->boot())
                ->toThrow(EmailVerificationRequired::class, 'registration.reveal_taken');
        });

        it('boots without email verification once the app says addresses may be revealed, or has no registration', function (array $config) {
            config($config);

            new KeyringServiceProvider($this->app)->boot();
        })->with([
            'revealing' => [['keyring.features' => [Features::registration()], 'keyring.registration.reveal_taken' => true]],
            'no registration' => [['keyring.features' => [Features::resetPasswords()]]],
        ])->throwsNoExceptions();

        it('refuses to register a user who can\'t verify an address, before saving anything', function () {
            config(['auth.providers.users.model' => PlainUser::class]);

            $this->withoutExceptionHandling();

            expect(fn () => $this->post('/register', registrationForm()))
                ->toThrow(EmailVerificationRequired::class, 'implement MustVerifyEmail on ['.PlainUser::class.']');

            expect(User::count())->toBe(0);
        });

        it('refuses to register without the email for a taken address, before saving anything', function () {
            Keyring::notifications(['already_registered' => null]);

            $this->withoutExceptionHandling();

            expect(fn () => $this->post('/register', registrationForm()))
                ->toThrow(MissingNotification::class, 'already_registered');

            expect(User::count())->toBe(0);
        });
    });
});

// What an app gets by setting registration.reveal_taken: the form says when
// an address is taken, and a new user is signed in straight away.
describe('saying when an address is taken', function () {
    beforeEach(function () {
        revealTakenAddresses();
    });

    it('registers and signs in like any other login', function () {
        $this->post('/register', registrationForm(['email' => 'Taylor@Example.com']))->assertRedirect('/dashboard');

        $user = User::sole();

        $this->assertAuthenticatedAs($user);
        Notification::assertSentToTimes($user, VerifyEmail::class, 1);
        expect($user->email)->toBe('taylor@example.com')
            ->and(app(SessionAssurance::class)->level())->toBe(Assurance::AAL1)
            ->and(Device::count())->toBe(1)
            ->and(app(SessionRegistry::class)->forUser($user))->toHaveCount(1);
    });

    it('says an address is taken, and creates and mails nothing', function (string $case) {
        $address = addressesToRegister()[$case]();
        $users = User::query()->withoutGlobalScopes()->count();

        $this->post('/register', registrationForm(['email' => $address]))
            ->assertSessionHasErrors(['email' => 'The email has already been taken.']);

        $this->assertGuest();
        Notification::assertNothingSent();
        expect(User::query()->withoutGlobalScopes()->count())->toBe($users);
    })->with(array_values(array_diff(array_keys(addressesToRegister()), ['free'])));

    it('says so next to whatever else is wrong with the form', function () {
        taylor();

        $this->post('/register', registrationForm(['name' => '', 'password' => 'password', 'password_confirmation' => 'password']))
            ->assertSessionHasErrors(['name', 'password', 'email' => 'The email has already been taken.']);
    });

    it('says so when another request took the address a moment before', function () {
        app()->bind(Registration::class, RacedRegistration::class);
        taylor();

        $this->post('/register', registrationForm())
            ->assertSessionHasErrors(['email' => 'The email has already been taken.']);

        expect(User::count())->toBe(1);
    });

    it('can leave new users signed out, for everyone or per user', function (bool|Closure $when) {
        Keyring::signInAfterRegistering($when);

        $this->post('/register', registrationForm())
            ->assertRedirect(route('login'))->assertSessionHas('status', 'registered');

        $this->assertGuest();
        expect(User::sole()->email)->toBe('taylor@example.com');
    })->with([
        'never' => false,
        'not this user' => fn () => fn (User $user) => $user->email === 'someone-else@example.com',
    ]);

    it('lets a user sign in before their address is verified', function () {
        taylor(['email_verified_at' => null]);

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    });

    it('verifies email addresses', function () {
        $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);

        $this->actingAs($user)->inertia()->get('/email/verify')->assertJsonPath('component', 'auth/verify-email');

        $this->post('/email/verification-notification')->assertSessionHas('status', 'verification-link-sent');

        $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)], absolute: false);

        $this->get($url)->assertRedirect('/dashboard?verified=1');
        expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
    });

    it('sends a signed-out browser that follows the link to sign in, and back to it', function () {
        $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
        $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)], absolute: false);

        $this->get($url)->assertRedirect(route('login'))->assertSessionMissing('status');
        $this->getJson($url)->assertUnauthorized();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(url($url));
        expect($user->fresh()->hasVerifiedEmail())->toBeFalse();

        $this->get($url)->assertRedirect('/dashboard?verified=1');
        expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
    });

    it('refuses a link that is for another account, or that was changed', function () {
        $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
        $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password']);

        $link = fn (User $for, string $email) => URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $for->id, 'hash' => sha1($email)], absolute: false);

        $this->actingAs($user)->get($link($other, $other->email))->assertForbidden();
        $this->get($link($user, 'an-older-address@example.com'))->assertForbidden();
        $this->get($link($user, $user->email).'0')->assertForbidden();

        expect($user->fresh()->hasVerifiedEmail())->toBeFalse()
            ->and($other->fresh()->hasVerifiedEmail())->toBeFalse();
    });

    it('adds the verified flag to a home url that has a query of its own', function () {
        config(['keyring.home' => '/dashboard?tab=security']);
        $user = User::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);

        $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)], absolute: false);

        $this->actingAs($user)->get($url)->assertRedirect('/dashboard?tab=security&verified=1');
    });

    describe('email verification', function () {
        it('refuses to register a MustVerifyEmail user without the verification feature, before saving anything', function () {
            withFeatures([Features::registration()]);

            $this->withoutExceptionHandling();

            expect(fn () => $this->post('/register', registrationForm()))->toThrow(EmailVerificationRequired::class, 'Features::emailVerification()');

            expect(User::count())->toBe(0);
        });

        it('stops someone who registered an address they don\'t own from adding a sign-in method', function () {
            $this->post('/register', registrationForm(['name' => 'Not Taylor']));

            // Signed in, but the address is unverified, so no passkey can be planted.
            $this->withAssurance(Assurance::AAL1)
                ->postJson(route('keyring.authenticators.store', 'passkey'))
                ->assertForbidden()
                ->assertJsonPath('message', __('keyring::keyring.verify_email_first'));
        });

        it('refuses to let users add sign-in methods with registration on when they can\'t verify an address', function () {
            config([
                'auth.providers.staff' => ['driver' => 'eloquent', 'model' => Staff::class],
                'auth.guards.staff' => ['driver' => 'session', 'provider' => 'staff'],
                'keyring.guard' => 'staff',
            ]);
            // The routes read the guard when they're registered.
            withFeatures(Features::all());

            $this->withoutExceptionHandling()->actingAs(staff(), 'staff')->withAssurance(Assurance::AAL1);

            expect(fn () => $this->postJson(route('keyring.authenticators.store', 'totp')))
                ->toThrow(EmailVerificationRequired::class, 'implement MustVerifyEmail');
        });

        it('lets an app that proves addresses its own way say who may add a sign-in method', function () {
            Keyring::allowEnrollmentWhen(fn ($user) => $user->name === 'Taylor');

            $this->actingAs(taylor(['email_verified_at' => null]))->withAssurance(Assurance::AAL1)
                ->postJson(route('keyring.authenticators.store', 'totp'))
                ->assertOk();

            $this->flushSession();

            $this->actingAs(taylor(['name' => 'Abigail', 'email' => 'abigail@example.com']))->withAssurance(Assurance::AAL1)
                ->postJson(route('keyring.authenticators.store', 'totp'))
                ->assertForbidden();
        });
    });
});
