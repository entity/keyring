<?php

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
use Keyring\Sessions\Sessions;

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
