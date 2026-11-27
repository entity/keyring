<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Enums\Assurance;
use Keyring\Enums\FreezeReason;
use Keyring\Enums\Purpose;
use Keyring\Events\AuthenticatorRemovalRefused;
use Keyring\Events\EnrollmentRefused;
use Keyring\Exceptions\SignInChangesFrozen;
use Keyring\Facades\Keyring;
use Keyring\Factors\EmailCode;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Models\SignInChange;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SigningToken;
use Keyring\Tests\Fixtures\User;

beforeEach(function () {
    $this->user = taylor();
    $this->totp = Authenticator::factory()->totp()->established()->for($this->user, 'authenticatable')->default()->create();
    $this->codes = Authenticator::factory()->recoveryCodes()->established()->for($this->user, 'authenticatable')->create();
});

/**
 * Sign in with the password and the authenticator app.
 */
function signInWithApp(Authenticator $totp, int $step = 0): TestResponse
{
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    return test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret, $step)]);
}

/**
 * Add a passkey through the real flow, as anyone holding the session could.
 */
function addPasskeyFromSession(): VirtualAuthenticator
{
    $key = new VirtualAuthenticator;
    $options = test()->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');
    test()->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();

    return $key;
}

function replaceRecoveryCodes(): TestResponse
{
    $started = test()->postJson(route('keyring.authenticators.store', 'recovery'));

    return $started->isOk() ? test()->postJson(route('keyring.authenticators.confirm', 'recovery')) : $started;
}

/**
 * Replace the user's one token with a new one.
 */
function replaceToken(): TestResponse
{
    $started = test()->postJson(route('keyring.authenticators.store', 'token'));

    return $started->isOk() ? test()->postJson(route('keyring.authenticators.confirm', 'token')) : $started;
}

function signOut(): void
{
    test()->post('/logout');
    test()->flushSession();
}

describe('a session that adds a passkey of its own', function () {
    beforeEach(function () {
        Keyring::require(Requirement::aal2()->ifEnrolled()->noDowngrade());
    });

    it('leaves the owner signing in with their password and app, and their recovery codes', function () {
        signInWithApp($this->totp)->assertRedirect('/dashboard');
        addPasskeyFromSession();

        replaceRecoveryCodes()->assertUnprocessable()->assertJsonPath('frozen.reason', 'new-authenticator');
        signOut();

        // The new key doesn't raise the bar yet, so the app is still asked for.
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'totp');
        $this->flushHeaders();

        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)])->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
        signOut();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
    });

    it('still signs in with the passkey it added', function () {
        signInWithApp($this->totp);
        $key = addPasskeyFromSession();
        signOut();

        $options = $this->getJson(route('keyring.login.options', 'passkey'))->json('options');
        $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
    });

    it('lets the owner remove that passkey, which unfreezes the account', function () {
        signInWithApp($this->totp);
        addPasskeyFromSession();
        signOut();

        signInWithApp($this->totp, 1)->assertRedirect('/dashboard');
        $passkey = $this->user->keyring->refresh()->of('passkey')->sole();

        $this->deleteJson(route('keyring.authenticators.destroy', $passkey->id))->assertOk();

        // Removing what wasn't established yet doesn't freeze anything.
        expect(SignInChange::query()->count())->toBe(0)
            ->and(app(AuthenticatorChanges::class)->frozen($this->user))->toBeNull();
        replaceRecoveryCodes()->assertOk();
    });

    it('makes the passkey count for noDowngrade once it is established', function () {
        signInWithApp($this->totp);
        addPasskeyFromSession();
        signOut();

        $this->travel(7)->days();
        $this->travel(1)->minute();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'passkey');
        $this->flushHeaders();

        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)])->assertSessionHasErrors();
        $this->assertGuest();
    });
});

it('refuses to remove the owner\'s app once a passkey is added, where the policy has no noDowngrade', function () {
    Keyring::require(Requirement::aal2()->ifEnrolled());
    signInWithApp($this->totp)->assertRedirect('/dashboard');
    addPasskeyFromSession();

    $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))
        ->assertUnprocessable()
        ->assertJsonValidationErrors('authenticator');
    replaceRecoveryCodes()->assertUnprocessable();
    signOut();

    signInWithApp($this->totp, 1)->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
    signOut();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect('/dashboard');
});

describe('while a new sign-in method is not established', function () {
    beforeEach(function () {
        $this->passkey = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    });

    it('answers JSON with why and until when', function () {
        $until = $this->passkey->created_at->addDays(7)->toIso8601String();

        $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))
            ->assertUnprocessable()
            ->assertExactJson([
                'message' => $message = __('keyring::keyring.frozen_new_authenticator', ['time' => '1 week']),
                'errors' => ['authenticator' => [$message]],
                'frozen' => ['reason' => 'new-authenticator', 'until' => $until, 'skip' => []],
            ]);

        expect($this->totp->fresh())->not->toBeNull();
    });

    it('answers a page request with the message as an error', function () {
        $this->from('/settings')->delete(route('keyring.authenticators.destroy', $this->totp->id))
            ->assertRedirect('/settings')
            ->assertSessionHasErrors('authenticator');

        expect($this->sessionErrors()->first('authenticator'))->toContain('another 1 week');
    });

    it('opens again once the newest method is established', function () {
        $this->travel(7)->days();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

        $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))->assertOk();
    });

    it('refuses new recovery codes before showing any', function () {
        $this->postJson(route('keyring.authenticators.store', 'recovery'))
            ->assertUnprocessable()
            ->assertJsonMissingPath('enrollment')
            ->assertJsonPath('frozen.reason', 'new-authenticator');
    });

    it('refuses new recovery codes from a session that began making them before it froze', function () {
        $this->passkey->delete();
        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();

        Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertUnprocessable();
        expect($this->user->keyring->refresh()->of('recovery')->sole()->is($this->codes))->toBeTrue();
    });

    it('makes the first recovery codes, which replace nothing', function () {
        $this->codes->delete();

        replaceRecoveryCodes()->assertOk();
        expect(SignInChange::query()->count())->toBe(0);
    });

    it('replaces a used-up set, which has nothing left to lose', function () {
        $this->codes->delete();
        Authenticator::factory()->recoveryCodes([])->established()->for($this->user, 'authenticatable')->create();

        replaceRecoveryCodes()->assertOk();
    });

    it('replaces recovery codes that aren\'t established yet, and freezes nothing for it', function () {
        $this->codes->forceFill(['created_at' => now()->subDay()])->save();

        replaceRecoveryCodes()->assertOk();
        replaceRecoveryCodes()->assertOk();

        expect($this->codes->fresh())->toBeNull()
            ->and(SignInChange::query()->count())->toBe(0);
    });

    it('removes other methods that are not established either', function () {
        $other = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $this->deleteJson(route('keyring.authenticators.destroy', $other->id))->assertOk();
    });

    it('goes on record, refused as frozen', function () {
        Event::fake([AuthenticatorRemovalRefused::class, EnrollmentRefused::class]);

        $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))->assertUnprocessable();
        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertUnprocessable();

        Event::assertDispatched(AuthenticatorRemovalRefused::class, fn (AuthenticatorRemovalRefused $event) => $event->reason === 'frozen' && $event->authenticator->is($this->totp));
        Event::assertDispatched(EnrollmentRefused::class, fn (EnrollmentRefused $event) => $event->reason === 'frozen' && $event->factor === 'recovery');
    });

    it('logs the refusal with its reason', function () {
        $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))->assertUnprocessable();

        expect(logEntry('authenticator_removal_refused')->meta)->toBe(['name' => 'Authenticator app', 'reason' => 'frozen']);
    });

    it('doesn\'t count an emailed code, which isn\'t a factor', function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, EmailCode::asExtraStep()]);
        $this->passkey->delete();
        Authenticator::factory()->emailCode()->for($this->user, 'authenticatable')->create();

        expect(app(AuthenticatorChanges::class)->frozen($this->user))->toBeNull();
    });
});

describe('after a sign-in method the account counted on is removed', function () {
    beforeEach(function () {
        $this->key = Authenticator::factory()->passkey()->established()->for($this->user, 'authenticatable')->create();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

        $this->deleteJson(route('keyring.authenticators.destroy', $this->key->id))->assertOk();
    });

    it('refuses to remove or replace another for a while', function () {
        $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))
            ->assertUnprocessable()
            ->assertJsonPath('frozen.reason', 'recent-change')
            ->assertJsonPath('frozen.until', now()->addDays(7)->toIso8601String());

        replaceRecoveryCodes()->assertUnprocessable()->assertJsonPath('frozen.reason', 'recent-change');
    });

    it('allows it again once that time is up', function () {
        $this->travel(7)->days();
        $this->flushSession();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

        replaceRecoveryCodes()->assertOk();

        // That was a change too, so the clock starts again.
        expect(app(AuthenticatorChanges::class)->frozen($this->user))
            ->reason->toBe(FreezeReason::RecentChange)
            ->until->toIso8601String()->toBe(now()->addDays(7)->toIso8601String());
    });

    it('is forgotten by keyring:prune once it holds nothing back', function () {
        $this->artisan('keyring:prune')->assertSuccessful();
        expect(SignInChange::query()->count())->toBe(1);

        $this->travel(7)->days();
        $this->travel(1)->second();

        $this->artisan('keyring:prune')->assertSuccessful();
        expect(SignInChange::query()->count())->toBe(0);
    });

    it('goes with a force deleted user', function () {
        $this->user->delete();

        expect(SignInChange::query()->count())->toBe(0);
    });
});

it('freezes on replacing recovery codes, as the first change to an account that was not frozen', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

    replaceRecoveryCodes()->assertOk();

    $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))
        ->assertUnprocessable()
        ->assertJsonPath('frozen.reason', 'recent-change');
});

it('lets the app\'s own code past the freeze when it says so, and freezes the account all the same', function () {
    $passkey = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
    $changes = app(AuthenticatorChanges::class);

    expect(fn () => $changes->remove($this->user, $this->totp->id))->toThrow(SignInChangesFrozen::class);

    $changes->remove($this->user, $this->totp->id, ignoreFreeze: true);
    $passkey->forceFill(['created_at' => now()->subMonth()])->save();

    $factor = Keyring::factor('recovery');
    expect(fn () => $changes->add($this->user, $factor, $factor->make($factor->generate()['secret'])))->toThrow(SignInChangesFrozen::class);

    $changes->add($this->user, $factor, $factor->make($factor->generate()['secret']), ignoreFreeze: true);

    expect($this->totp->fresh())->toBeNull()
        ->and($this->codes->fresh())->toBeNull()
        ->and($changes->frozen($this->user)->reason)->toBe(FreezeReason::RecentChange);
});

it('can be turned off', function () {
    config(['keyring.authenticator_changes.established_after' => 0]);
    Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

    replaceRecoveryCodes()->assertOk();
    $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))->assertOk();
});

describe('which keys raise the bar', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys()->requireAttestation(), Totp::class, RecoveryCodes::class]);
        Keyring::fake()->pass('security-key');
    });

    it('asks a fresh verification for an established key that can\'t leave its device, not a new one', function (bool $established, bool $mayRemoveWithApp) {
        $key = Authenticator::factory()->securityKey()->attested('2fc0579f-8113-47ea-b116-bb5a8db9202a')->for($this->user, 'authenticatable')
            ->when($established, fn ($factory) => $factory->established())
            ->create();

        $this->actingAs($this->user)->verifiedWith($this->totp);

        $this->deleteJson(route('keyring.authenticators.destroy', $key->id))->assertStatus($mayRemoveWithApp ? 200 : 423);
    })->with([
        'a new key, which the owner can remove with what they had' => [false, true],
        'an established key' => [true, false],
    ]);

    it('still takes a new key for a route that asks for aal3 itself', function () {
        Keyring::require(Requirement::aal3());
        Authenticator::factory()->securityKey()->attested('2fc0579f-8113-47ea-b116-bb5a8db9202a')->for($this->user, 'authenticatable')->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->post(route('keyring.login.verify', 'security-key'))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
    });

    it('doesn\'t let a passkey added from a session raise what an ifEnrolled policy asks for', function () {
        Keyring::require(Requirement::aal2()->phishingResistant()->ifEnrolled());
        signInWithApp($this->totp)->assertRedirect('/dashboard');
        addPasskeyFromSession();
        signOut();

        // Without the passkey, and with no recovery code spent.
        signInWithApp($this->totp, 1)->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
        signOut();

        $passkey = $this->user->keyring->refresh()->of('passkey')->sole();
        $this->actingAs($this->user)->verifiedWith($this->totp);
        $this->deleteJson(route('keyring.authenticators.destroy', $passkey->id))->assertOk();
    });

    it('only lets an established key raise what an ifEnrolled policy asks for', function (Closure $policy, Closure $key, string $factor, bool $established) {
        Keyring::require($policy());
        $added = $key()->for($this->user, 'authenticatable')
            ->when($established, fn ($factory) => $factory->established())
            ->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', $established ? $factor : 'totp');
        $this->flushHeaders();

        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret)]);
        $established ? $this->assertGuest() : $this->assertAuthenticatedAs($this->user);
        signOut();

        // A fresh verification with the app removes a new key, never an established one.
        $this->actingAs($this->user)->verifiedWith($this->totp);
        $this->deleteJson(route('keyring.authenticators.destroy', $added->id))->assertStatus($established ? 423 : 200);
    })->with([
        'phishing resistant' => [fn () => Requirement::aal2()->phishingResistant()->ifEnrolled(), fn () => Authenticator::factory()->passkey(), 'passkey'],
        'device bound' => [fn () => Requirement::aal2()->deviceBound()->ifEnrolled(), fn () => Authenticator::factory()->securityKey(), 'security-key'],
        'aal3' => [fn () => Requirement::aal3()->ifEnrolled(), fn () => Authenticator::factory()->securityKey()->attested('2fc0579f-8113-47ea-b116-bb5a8db9202a'), 'security-key'],
    ])->with([
        'a new key' => [false],
        'an established key' => [true],
    ]);

    it('doesn\'t let a key of a new kind added from a session raise how many factors an ifEnrolled policy asks for', function () {
        Keyring::require(Requirement::factors(3)->ifEnrolled());
        signInWithApp($this->totp)->assertRedirect('/dashboard');
        $key = addPasskeyFromSession();
        signOut();

        // The password and app are still enough, with no recovery code spent.
        signInWithApp($this->totp, 1)->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
        signOut();

        // The new passkey is offered, and counts when it's used.
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $challenge = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'totp');
        $this->flushHeaders();
        expect(collect($challenge->json('props.alternatives'))->pluck('factor'))->toContain('passkey');

        $options = $this->inertia()->get(route('keyring.login.challenge', ['factor' => 'passkey']))->json('props.challenge.options');
        $this->flushHeaders();
        $this->post(route('keyring.login.verify', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');
        signOut();

        // Once it's established, it's asked for as the third.
        $this->travel(7)->days();
        $this->travel(1)->minute();

        signInWithApp($this->totp);
        $this->assertGuest();

        $options = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'passkey')->json('props.challenge.options');
        $this->flushHeaders();
        $this->post(route('keyring.login.verify', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($this->user);
    });

    it('asks a fresh verification for no more than the established factors give', function () {
        Keyring::require(Requirement::factors(3)->ifEnrolled());
        $passkey = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

        $this->actingAs($this->user)->verifiedWith($this->totp);

        $this->deleteJson(route('keyring.authenticators.destroy', $passkey->id))->assertOk();
    });

    it('asks for the owner\'s own new factor where adding it took the password, and only there', function (bool $password, int $factors) {
        Keyring::require(Requirement::aal2()->ifEnrolled());
        $this->totp->delete();
        if (! $password) {
            Keyring::withoutProtection(fn () => $this->user->forceFill(['password' => null])->save());
        }
        Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

        $requirement = Keyring::requirementFor($this->user, Attempt::start(Purpose::Login, $this->user));

        expect($requirement->factors)->toBe($factors);
    })->with([
        'a password, which a copy of the session can\'t add a factor without' => [true, 2],
        'no password, so anyone with the session could have added it' => [false, 1],
    ]);

    it('only counts established keys for noDowngrade', function (bool $established, string $factor) {
        Keyring::require(Requirement::aal2()->noDowngrade());
        Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')
            ->when($established, fn ($factory) => $factory->established())
            ->create();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

        $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', $factor);
    })->with([
        'a new key' => [false, 'totp'],
        'an established key' => [true, 'security-key'],
    ]);
});

it('says which authenticators are established', function () {
    $user = User::query()->findOrFail($this->user->id);

    expect($user->keyring->isEstablished($this->totp))->toBeTrue()
        ->and($user->keyring->isEstablished(Authenticator::factory()->totp()->for($user, 'authenticatable')->create()))->toBeFalse()
        ->and($user->keyring->isEstablished($user->keyring->of('password')->sole()))->toBeTrue();
});

describe('recovery codes', function () {
    it('are established once the account has had them a while, by their own date', function () {
        $keyring = $this->user->keyring;
        $young = Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

        expect($keyring->isEstablished($this->codes))->toBeTrue()
            ->and($keyring->isEstablished($young))->toBeFalse();
    });

    it('freeze nothing on their own while they\'re new', function () {
        $this->codes->forceFill(['created_at' => now()])->save();

        expect(app(AuthenticatorChanges::class)->frozen($this->user))->toBeNull();
    });

    it('can be replaced straight after turning on two factor', function () {
        $this->totp->delete();
        $this->codes->delete();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

        $secret = $this->postJson(route('keyring.authenticators.store', 'totp'), ['password' => 'password'])->json('enrollment.secret');
        $this->postJson(route('keyring.authenticators.confirm', 'totp'), ['code' => totpCode($secret)])->assertOk();

        replaceRecoveryCodes()->assertOk();
    });

    it('stay frozen once established, while a new method isn\'t', function () {
        Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

        replaceRecoveryCodes()->assertUnprocessable()->assertJsonPath('frozen.reason', 'new-authenticator');
        $this->deleteJson(route('keyring.authenticators.destroy', $this->codes->id))->assertUnprocessable();

        expect($this->codes->fresh())->not->toBeNull();
    });
});

describe('a factor a user has one of', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, SigningToken::class]);
        $this->token = Authenticator::factory()->established()->for($this->user, 'authenticatable')->create(['factor' => 'token', 'name' => 'Token', 'secret' => 'old']);
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    });

    it('replaces an established one as a change the account counted on, which freezes it', function () {
        replaceToken()->assertOk();

        expect($this->token->fresh())->toBeNull()
            ->and(app(AuthenticatorChanges::class)->frozen($this->user))->not->toBeNull()
            ->and(SignInChange::query()->count())->toBe(1);
    });

    it('won\'t replace an established one while frozen, before showing anything', function () {
        Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

        replaceToken()
            ->assertUnprocessable()
            ->assertJsonMissingPath('enrollment')
            ->assertJsonPath('frozen.reason', 'new-authenticator');

        expect($this->token->fresh())->not->toBeNull();
    });

    it('replaces one that isn\'t established yet, freezing nothing for it', function () {
        $this->token->forceFill(['created_at' => now()->subDay()])->save();
        Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create();

        replaceToken()->assertOk();

        expect($this->token->fresh())->toBeNull()
            ->and(SignInChange::query()->count())->toBe(0);
    });
});

describe('renaming', function () {
    beforeEach(function () {
        $this->passkey = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create(['name' => 'New key']);
        $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    });

    it('won\'t rename an established method while frozen', function () {
        $this->patchJson(route('keyring.authenticators.update', $this->totp->id), ['name' => 'Remove me'])
            ->assertUnprocessable()
            ->assertJsonPath('frozen.reason', 'new-authenticator');

        expect($this->totp->fresh()->name)->not->toBe('Remove me');
    });

    it('renames a newer one, keeps a name as it is, and chooses the default', function () {
        $this->patchJson(route('keyring.authenticators.update', $this->passkey->id), ['name' => 'Phone'])->assertOk();
        $this->patchJson(route('keyring.authenticators.update', $this->totp->id), ['name' => $this->totp->name])->assertOk();
        $this->patchJson(route('keyring.authenticators.update', $this->passkey->id), ['default' => true])->assertOk();

        expect($this->passkey->fresh())->name->toBe('Phone')->is_default->toBeTrue()
            ->and(SignInChange::query()->count())->toBe(0);
    });

    it('renames an established one once nothing is frozen, freezing nothing for it', function () {
        $this->passkey->delete();

        $this->patchJson(route('keyring.authenticators.update', $this->totp->id), ['name' => 'Work phone'])->assertOk();

        expect($this->totp->fresh()->name)->toBe('Work phone')
            ->and(app(AuthenticatorChanges::class)->frozen($this->user))->toBeNull();
    });

    it('lets the app\'s own code rename one while frozen', function () {
        expect(fn () => app(AuthenticatorChanges::class)->update($this->totp, ['name' => 'Work phone']))->toThrow(SignInChangesFrozen::class);

        app(AuthenticatorChanges::class)->update($this->totp, ['name' => 'Work phone'], ignoreFreeze: true);

        expect($this->totp->fresh()->name)->toBe('Work phone');
    });
});
