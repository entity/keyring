<?php

namespace Keyring\Testing;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;
use Keyring\Contracts\Enrollable;
use Keyring\Contracts\Factor;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Exceptions\ProtectedAttributeException;
use Keyring\Facades\Keyring;
use Keyring\Features;
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

        foreach (Keyring::protectedAttributes() as $attribute) {
            try {
                $user->fresh()->update([$attribute => $attribute === 'password' ? 'something-new-and-long' : 'changed-'.uniqid().'@example.com']);
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
