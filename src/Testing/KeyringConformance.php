<?php

declare(strict_types=1);

namespace Keyring\Testing;

use Illuminate\Auth\Middleware\Authenticate;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Routing\Route;
use Illuminate\Support\Arr;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\Factor;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Http\Middleware\AuthenticateSession;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;

/**
 * Checks that your Keyring setup (policy, factors, responses, pipeline
 * changes) still keeps the guarantees Keyring promises. Add it to a test
 * class in your app:
 *
 *     class KeyringTest extends TestCase
 *     {
 *         use RefreshDatabase, KeyringConformance;
 *
 *         protected function keyringUser(): User
 *         {
 *             return User::factory()->create(['password' => 'password']);
 *         }
 *     }
 *
 * Works with PHPUnit and Pest.
 */
trait KeyringConformance
{
    use InteractsWithKeyring;

    /**
     * A user whose password is "password", whose email is verified, and who
     * has no extra factors.
     */
    abstract protected function keyringUser(): Authenticatable&Model;

    protected function keyringPassword(): string
    {
        return 'password';
    }

    /**
     * Mandatory pipeline steps your app removes or replaces on purpose, with
     * dangerouslyRemove() or dangerouslyReplace().
     *
     * @return list<class-string>
     */
    protected function keyringAcknowledgedDangerousSteps(): array
    {
        return [];
    }

    /**
     * What your registration form posts for an address. Override it when
     * your CreatesNewUsers action validates other fields.
     *
     * @return array<string, mixed>
     */
    protected function keyringRegistration(string $email): array
    {
        return [
            'name' => 'Avery Quinn',
            Keyring::email() => $email,
            'password' => 'Xk4-mR9vTq2-Lw7bZp5-Hd3n',
            'password_confirmation' => 'Xk4-mR9vTq2-Lw7bZp5-Hd3n',
        ];
    }

    /**
     * Routes, by URI, that sign in to Keyring's guard without its session
     * middleware on purpose. A revoked or timed-out session keeps working on
     * them until Laravel's own session ends.
     *
     * @return list<string>
     */
    protected function keyringAcknowledgedUncheckedRoutes(): array
    {
        return [];
    }

    /**
     * Whether your app keeps bcrypt on purpose, knowing its passwords stop
     * at 72 bytes: 72 plain characters, and fewer of any other kind.
     */
    protected function keyringAcknowledgesBcryptLimit(): bool
    {
        return false;
    }

    public function test_keyring_signs_in_with_a_password_or_asks_for_more(): void
    {
        $user = $this->keyringUser();

        $response = $this->post(route('login.store'), [
            Keyring::username() => $user->getAttribute(Keyring::username()),
            'password' => $this->keyringPassword(),
        ]);

        $response->assertRedirect();

        $this->assertTrue(
            Keyring::guard()->check() || str_contains((string) $response->headers->get('Location'), route('keyring.login.challenge')),
            'A correct password should either sign in or lead to the challenge page.',
        );
    }

    public function test_keyring_keeps_its_mandatory_pipeline_steps(): void
    {
        $this->assertSame(
            [],
            array_values(array_diff(Keyring::dangerouslyChangedSteps(), $this->keyringAcknowledgedDangerousSteps())),
            'Mandatory pipeline steps were removed or replaced. If you meant to, list them in keyringAcknowledgedDangerousSteps().',
        );
    }

    public function test_keyring_takes_passwords_of_64_characters(): void
    {
        $this->assertGreaterThanOrEqual(64, config('keyring.passwords.max'), 'The keyring.passwords.max option should allow passwords of at least 64 characters.');

        $this->assertTrue(
            Hash::getDefaultDriver() !== 'bcrypt' || $this->keyringAcknowledgesBcryptLimit(),
            'Passwords are hashed with bcrypt, which only reads the first 72 bytes, so Keyring refuses longer ones: 64 characters of accented or non-Latin text, for one. '
            .'Set HASH_DRIVER=argon2id to take every password up to keyring.passwords.max, with HASH_VERIFY=false while users still have bcrypt hashes. '
            .'If you mean to keep bcrypt, return true from keyringAcknowledgesBcryptLimit().',
        );
    }

    /**
     * The options production hashes passwords with, when your tests hash
     * with less: Laravel's own phpunit.xml sets BCRYPT_ROUNDS=4. Bcrypt is
     * timed at 12 rounds, a new app's setting, unless yours is higher.
     * Return your own to time what production runs.
     *
     * @return array<string, mixed>
     */
    protected function keyringProductionHashOptions(): array
    {
        return Hash::getDefaultDriver() === 'bcrypt' ? ['rounds' => max(12, (int) config('hashing.bcrypt.rounds'))] : [];
    }

    /**
     * A refused sign in or reset is held for keyring.timebox so that how
     * long it took doesn't say whether the account exists. Nothing is held
     * shorter than the work already done, and the slowest thing a refusal
     * does is hash a password, at a cost that differs between accounts while
     * old hashes are being moved to a new one. So the wait only hides the
     * difference while it's longer than a hash.
     *
     * This times one on the machine the tests run on, which is a guide and
     * not your servers: slower ones need a longer timebox.
     */
    public function test_keyring_holds_a_refusal_for_longer_than_a_password_hash_takes(): void
    {
        $timebox = Duration::milliseconds(config('keyring.timebox'));

        $took = min(array_map(function () {
            $started = hrtime(true);
            Hash::make(Str::random(32), $this->keyringProductionHashOptions());

            return (hrtime(true) - $started) / 1_000_000;
        }, range(1, 3)));

        $this->assertLessThan(
            $timebox,
            (int) ceil($took),
            sprintf('One password hash took %dms here and keyring.timebox is %dms, so a refusal that hashes takes longer than one that doesn\'t, and shows which accounts exist. ', (int) ceil($took), $timebox)
            .'Set keyring.timebox comfortably above what a hash takes on your servers, or return what production hashes with from keyringProductionHashOptions().',
        );
    }

    /**
     * Keyring's own limit on asking for a reset link is per sender. How
     * often one account can be sent one is the broker's "throttle", which is
     * Laravel's setting and yours: 60 seconds in a new app.
     */
    public function test_keyring_limits_how_often_an_account_is_sent_a_reset_link(): void
    {
        if (! Features::enabled(Features::resetPasswords())) {
            $this->markTestSkipped('Password resets are off: turn on Features::resetPasswords().');
        }

        $option = 'auth.passwords.'.(config('keyring.passwords.broker') ?? config('auth.defaults.passwords')).'.throttle';

        $this->assertGreaterThan(
            0,
            (int) config($option),
            "The [{$option}] option is missing or zero, so one account can be sent a reset link as often as anyone asks, from as many addresses as they have. "
            .'Set it to the seconds an account waits between links: 60 is what a new Laravel app has.',
        );
    }

    public function test_keyring_gives_the_same_error_for_wrong_passwords_and_unknown_accounts(): void
    {
        $user = $this->keyringUser();
        $field = Keyring::username();

        $this->post(route('login.store'), [$field => $user->getAttribute($field), 'password' => 'definitely-wrong']);
        $wrong = $this->sessionErrors()->first($field);

        $this->post(route('login.store'), [$field => 'nobody-'.uniqid().'@example.com', 'password' => 'definitely-wrong']);
        $unknown = $this->sessionErrors()->first($field);

        $this->assertNotSame('', $wrong);
        $this->assertSame($wrong, $unknown, 'Login errors must not reveal which accounts exist.');
        $this->assertGuest();
    }

    public function test_keyring_registers_a_taken_address_like_a_free_one(): void
    {
        if (! Keyring::hidesRegisteredAddresses()) {
            $this->markTestSkipped('Registration is off, or the registration.reveal_taken option lets it say when an address is taken.');
        }

        $field = Keyring::email();
        $answers = [];

        foreach (['taken' => (string) $this->keyringUser()->getAttribute($field), 'free' => 'nobody-'.uniqid().'@example.com'] as $case => $address) {
            $response = $this->post(route('register.store'), $this->keyringRegistration($address));

            $answers[$case] = [
                'status' => $response->getStatusCode(),
                'location' => $response->headers->get('Location'),
                'flashed' => session('status'),
                'errors' => $this->sessionErrors()->toArray(),
                'signed in' => Keyring::guard()->check(),
            ];
        }

        $this->assertSame([], $answers['free']['errors'], 'Your CreatesNewUsers action refused the form. Return one it accepts from keyringRegistration().');
        $this->assertSame($answers['free'], $answers['taken'], 'Registration must answer the same for an address that has an account. Don\'t check in your CreatesNewUsers action whether it\'s taken: Keyring does.');
        $this->assertFalse($answers['free']['signed in'], 'Registering must not sign a new user in, or a taken address would show.');
    }

    public function test_keyring_protects_email_and_password(): void
    {
        $user = $this->keyringUser();

        if (Keyring::protectedAttributes() === []) {
            $this->markTestSkipped('Nothing is protected: Features::updatePasswords() protects the password, and Features::emailChanges() the email.');
        }

        foreach (Keyring::protectedAttributes($user) as $attribute) {
            try {
                // Filled by force: an attribute that isn't fillable would be dropped
                // by update(), and look changed when nothing was even tried.
                ($user->fresh() ?? $user)->forceFill([$attribute => $attribute === $user->getAuthPasswordName() ? 'something-new-and-long' : 'changed-'.uniqid().'@example.com'])->save();
                $this->fail("The [{$attribute}] attribute changed outside a Keyring flow.");
            } catch (ProtectedAttributeException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_keyring_requires_a_fresh_verification_to_change_sign_in_methods(): void
    {
        $user = $this->keyringUser();
        $factor = $this->enrollableFactors()->first();

        if ($factor === null) {
            $this->markTestSkipped('No sign-in methods to set up: register some, and turn on Features::manageAuthenticators().');
        }

        $this->actingAs($user)->withAssurance(Assurance::AAL1)->freshAt(now()->subDay())
            ->postJson(route('keyring.authenticators.store', $factor->key()))
            ->assertStatus(423);
    }

    public function test_keyring_lets_every_enrollable_factor_begin_enrolling(): void
    {
        $user = $this->keyringUser();

        if ($this->enrollableFactors()->isEmpty()) {
            $this->markTestSkipped('No sign-in methods to set up: register some, and turn on Features::manageAuthenticators().');
        }

        foreach ($this->enrollableFactors() as $factor) {
            $this->actingAs($user)->withAssurance(Assurance::AAL1)
                ->postJson(route('keyring.authenticators.store', $factor->key()))
                ->assertOk();
        }
    }

    public function test_keyring_revokes_the_session_on_sign_out(): void
    {
        $user = $this->keyringUser();

        // Any request registers the session; a signed-in user is sent home from the login page.
        $this->actingAs($user)->withAssurance(Assurance::AAL1)->get(route('login'))->assertRedirect();
        $id = session(Sessions::KEY);

        $this->post(route('logout'));

        $this->assertNotNull($id, 'Signed-in sessions should be registered.');
        $this->assertNotNull(app(SessionRegistry::class)->find($id)?->revokedAt, 'Signing out should revoke the registered session.');
    }

    /**
     * What a registry revokes is what it reports, so anything built on it
     * (events for each session that ends, say) misses none. A custom
     * SessionRegistry driver, or anything wrapping one, has to say which
     * records each call revoked.
     */
    public function test_keyring_registry_returns_the_sessions_it_revokes(): void
    {
        $user = $this->keyringUser();
        $registry = app(SessionRegistry::class);
        $now = now()->getTimestamp();

        $device = 'conformance-'.Str::random(10);
        $ids = fn (Collection $sessions) => $sessions->map(fn (RegisteredSession $session) => $session->id)->all();

        // One to revoke alone, two on one device, the one kept, and one more.
        [$alone, $phone, $tablet, $kept, $other] = array_map(function (?string $deviceId) use ($user, $registry, $now) {
            $registry->save($session = new RegisteredSession(Str::random(40), (string) $user->getAuthIdentifier(), RegisteredSession::typeOf($user), (string) config('keyring.guard'), $deviceId, Assurance::AAL1, null, null, $now, $now, $now + 3600));

            return $session->id;
        }, [null, $device, $device, null, null]);

        $first = $registry->revoke($alone);

        $this->assertSame($alone, $first?->id, 'Your SessionRegistry\'s revoke() should return the record it revoked, or null only when it revoked nothing.');
        $this->assertNotNull($first->revokedAt, 'Your SessionRegistry\'s revoke() should return the record as it now stands, with revokedAt set.');
        $this->assertNull(
            $registry->revoke($alone),
            'Your SessionRegistry\'s revoke() should return null for a record that was revoked already: it revoked nothing this time.',
        );

        $revoked = $registry->revokeDevice($user, $device);

        $this->assertEqualsCanonicalizing([$phone, $tablet], $ids($revoked), 'Your SessionRegistry\'s revokeDevice() should return every record it revoked on the device, and only those.');
        $this->assertTrue(
            $revoked->every(fn (RegisteredSession $session) => $session->revokedAt !== null),
            'Your SessionRegistry\'s revokeDevice() should return each record as it now stands, with revokedAt set.',
        );
        $this->assertTrue($registry->revokeDevice($user, $device)->isEmpty(), 'Your SessionRegistry\'s revokeDevice() should return nothing when it revoked nothing.');

        $revoked = $registry->revokeAll($user, except: $kept);

        $this->assertEqualsCanonicalizing(
            [$other],
            $ids($revoked),
            'Your SessionRegistry\'s revokeAll() should return every record it revoked, and only those: not ones revoked already, nor the one it was told to leave.',
        );
        $this->assertTrue(
            $revoked->every(fn (RegisteredSession $session) => $session->revokedAt !== null),
            'Your SessionRegistry\'s revokeAll() should return each record as it now stands, with revokedAt set.',
        );
        $this->assertNull($registry->find($kept)?->revokedAt, 'Your SessionRegistry\'s revokeAll() should leave the record it was told to leave ($except).');
        $this->assertTrue($registry->revokeAll($user, except: $kept)->isEmpty(), 'Your SessionRegistry\'s revokeAll() should return nothing when it revoked nothing.');
    }

    public function test_keyring_checks_the_session_on_every_signed_in_route(): void
    {
        $router = app('router');

        $unchecked = new Collection($router->getRoutes()->getRoutes())
            ->filter(function (Route $route) use ($router) {
                $middleware = array_filter($router->gatherRouteMiddleware($route), is_string(...));

                return $this->signsInToKeyringsGuard($middleware) && ! in_array(AuthenticateSession::class, $middleware, true);
            })
            ->map(fn (Route $route) => $route->uri())
            ->unique()
            ->diff($this->keyringAcknowledgedUncheckedRoutes())
            ->values()
            ->all();

        $this->assertSame(
            [],
            $unchecked,
            'These routes use the auth middleware for Keyring\'s guard without keyring.session, so a session that was revoked or timed out keeps working on them: '.implode(', ', $unchecked).'. Add keyring.session to their group, or list them in keyringAcknowledgedUncheckedRoutes().',
        );
    }

    /**
     * Whether a route's middleware includes "auth" for Keyring's guard: by
     * name, as the default guard, or through Sanctum where it signs a
     * single-page app in with the session guards it's given. Sanctum's
     * token-only routes have no session to check.
     *
     * @param  array<array-key, string>  $middleware
     */
    protected function signsInToKeyringsGuard(array $middleware): bool
    {
        $guard = config('keyring.guard');

        $throughSanctum = in_array('Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful', $middleware, true)
            && in_array($guard, Arr::wrap(config('sanctum.guard', 'web')), true);

        return array_any($middleware, function (string $middleware) use ($guard, $throughSanctum) {
            $class = Str::before($middleware, ':');
            $guards = str_contains($middleware, ':') ? explode(',', Str::after($middleware, ':')) : [config('auth.defaults.guard')];

            return is_a($class, Authenticate::class, true)
                && (in_array($guard, $guards, true) || ($throughSanctum && in_array('sanctum', $guards, true)));
        });
    }

    /**
     * The factors users can add themselves, when they're allowed to.
     *
     * @return Collection<int, Enrollable>
     */
    protected function enrollableFactors(): Collection
    {
        if (! Features::enabled(Features::manageAuthenticators())) {
            return new Collection;
        }

        return Keyring::registered()->filter(fn (Factor $factor) => $factor instanceof Enrollable)->values();
    }
}
