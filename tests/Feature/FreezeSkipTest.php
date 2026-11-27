<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\FreezeSkips;
use Keyring\Enums\FreezeReason;
use Keyring\Events\FactorFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\SingleSignOn;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Models\SignInChange;
use Keyring\Notifications\AuthenticatorAdded as AuthenticatorAddedNotice;
use Keyring\Notifications\PasswordChanged as PasswordChangedNotice;
use Keyring\Notifications\RecoveryCodesGenerated as RecoveryCodesGeneratedNotice;
use Keyring\Sessions\Sessions;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\SigningToken;
use Keyring\Tests\Fixtures\User;
use PragmaRX\Google2FA\Google2FA;

beforeEach(function () {
    Route::middleware(['web', 'auth', 'keyring.fresh:15m'])->get('/account', fn () => 'danger zone');

    $this->user = taylor();
    $this->totp = Authenticator::factory()->totp()->established()->for($this->user, 'authenticatable')->default()->create();
    $this->codes = Authenticator::factory()->recoveryCodes()->established()->for($this->user, 'authenticatable')->create();

    // The owner's passkey, which they've had for a month.
    $this->key = new VirtualAuthenticator(synced: true);
    $this->passkey = Authenticator::factory()->passkey()->established()->for($this->user, 'authenticatable')->create(skipRow($this->user, $this->key));
});

/**
 * A real key's row, so it can answer a challenge.
 *
 * @return array{credential_id: string, public_key: string}
 */
function skipRow(User $user, VirtualAuthenticator $key): array
{
    ['credential_id' => $id, 'credential' => $record] = passkeyRow($user, $key);

    return ['credential_id' => $id, 'public_key' => $record];
}

/**
 * Sign in for real, with the password and the authenticator app.
 */
function signInForSkip(Authenticator $totp, int $step = 0): void
{
    test()->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    test()->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($totp->secret, $step)])->assertRedirect('/dashboard');
}

/**
 * Whoever holds the session adds a passkey of their own, which freezes the account.
 */
function plantPasskey(User $user): Authenticator
{
    return Authenticator::factory()->passkey()->for($user, 'authenticatable')->create();
}

/**
 * @return array<string, mixed>
 */
function skipOptions(string $action, string $target, string $factor = 'passkey', ?string $name = null): array
{
    return test()->postJson(route('keyring.authenticators.proof-options', $factor), ['action' => $action, 'target' => $target, ...($name === null ? [] : ['name' => $name])])
        ->assertOk()
        ->json('options');
}

/**
 * @param  array<string, mixed>  $proof
 */
function removeWithProof(Authenticator $authenticator, array $proof): TestResponse
{
    return test()->deleteJson(route('keyring.authenticators.destroy', $authenticator->id), ['proof' => $proof]);
}

describe('a frozen account', function () {
    beforeEach(function () {
        // Another passkey the owner has had a while, to remove. Removing the
        // app the session signed in with would take its fresh verification.
        $this->spare = Authenticator::factory()->passkey()->established()->for($this->user, 'authenticatable')->create(['name' => 'Old phone']);

        signInForSkip($this->totp);
        $this->planted = plantPasskey($this->user);
    });

    it('says a removal can be made now with the owner\'s established passkey', function () {
        $this->deleteJson(route('keyring.authenticators.destroy', $this->spare->id))
            ->assertUnprocessable()
            ->assertJsonPath('frozen.reason', 'new-authenticator')
            ->assertJsonPath('frozen.skip', ['passkey']);

        expect($this->spare->fresh())->not->toBeNull();
    });

    it('says so for new recovery codes too', function () {
        $this->postJson(route('keyring.authenticators.store', 'recovery'))
            ->assertUnprocessable()
            ->assertJsonPath('frozen.skip', ['passkey']);
    });

    it('removes exactly the authenticator the key signed for, and starts the clock again', function () {
        $this->freezeSecond();

        $options = skipOptions('remove', $this->spare->id);

        expect(array_column($options['allowCredentials'], 'id'))->toContain($this->passkey->credential_id)
            ->not->toContain($this->planted->credential_id);

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $this->key->assert($options)])->assertOk();

        expect($this->spare->fresh())->toBeNull()
            ->and($this->passkey->fresh()->last_used_at)->not->toBeNull()
            ->and(SignInChange::query()->sole()->changed_at->toIso8601String())->toBe(now()->toIso8601String());

        // Once the planted key goes, what's left is the change just made.
        $this->deleteJson(route('keyring.authenticators.destroy', $this->planted->id))->assertOk();
        expect(app(AuthenticatorChanges::class)->frozen($this->user))
            ->reason->toBe(FreezeReason::RecentChange)
            ->until->toIso8601String()->toBe(now()->addDays(7)->toIso8601String());
    });

    it('doesn\'t take the same answer twice', function () {
        $credential = $this->key->assert(skipOptions('remove', $this->spare->id));

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])->assertOk();

        // Even with a challenge for the next change waiting in the session.
        skipOptions('remove', $this->codes->id);
        removeWithProof($this->codes, ['factor' => 'passkey', 'credential' => $credential])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        expect($this->codes->fresh())->not->toBeNull();
    });

    it('doesn\'t take an answer sent again from an earlier copy of the session', function () {
        $options = skipOptions('remove', $this->spare->id);
        $earlier = session()->all();
        $credential = $this->key->assert($options);

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])->assertOk();

        // The earlier copy still holds the challenge, but it was used up.
        sendBackSession($earlier);

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);
    });

    it('refuses an answer signed for another authenticator, and uses its challenge up', function () {
        $options = skipOptions('remove', $this->codes->id);
        $earlier = session()->all();
        $credential = $this->key->assert($options);

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        // Nor can it be sent again for the change it was for, from a copy
        // of the session that still holds the challenge.
        sendBackSession($earlier);
        removeWithProof($this->codes, ['factor' => 'passkey', 'credential' => $credential])->assertUnprocessable()->assertJsonValidationErrors('proof');

        expect($this->spare->fresh())->not->toBeNull()
            ->and($this->codes->fresh())->not->toBeNull();
    });

    it('refuses an answer signed for another kind of change', function () {
        $credential = $this->key->assert(skipOptions('replace', 'recovery'));

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])->assertUnprocessable()->assertJsonValidationErrors('proof');

        expect($this->spare->fresh())->not->toBeNull();
    });

    it('refuses a removal with no challenge asked for', function () {
        $credential = $this->key->assert(['challenge' => 'bm90IGEgY2hhbGxlbmdl', 'rpId' => 'localhost']);

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])->assertUnprocessable()->assertJsonValidationErrors('proof');
    });

    it('refuses an answer that comes too late', function () {
        $credential = $this->key->assert(skipOptions('remove', $this->spare->id));
        $this->travel(5)->minutes();
        $this->travel(1)->second();

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])->assertUnprocessable()->assertJsonValidationErrors('proof');
    });

    it('refuses a wrong answer, which counts as a failure', function () {
        Event::fake([FactorFailed::class]);
        $options = skipOptions('remove', $this->spare->id);

        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => new VirtualAuthenticator()->assert($options)])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('proof');

        Event::assertDispatched(FactorFailed::class, fn (FactorFailed $event) => $event->factor === 'passkey' && $event->attempt->user()->is($this->user));
        expect($this->spare->fresh())->not->toBeNull();
    });

    it('refuses the answer to a sign-in challenge', function () {
        signOutForSkip();

        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
        $options = $this->inertia()->get(route('keyring.login.challenge', 'passkey'))->json('props.challenge.options');
        $this->flushHeaders();
        $credential = $this->key->assert($options);
        $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)])->assertRedirect('/dashboard');

        skipOptions('remove', $this->spare->id);
        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $credential])->assertUnprocessable()->assertJsonValidationErrors('proof');

        expect($this->spare->fresh())->not->toBeNull();
    });

    it('refuses the answer to a step-up challenge, and a step-up its answer', function () {
        $this->travel(16)->minutes();
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
        $stepUp = $this->key->assert($this->inertia()->get(route('keyring.confirm.challenge', 'passkey'))->json('props.challenge.options'));
        $this->flushHeaders();
        $this->post(route('keyring.confirm.verify', 'totp'), ['code' => totpCode($this->totp->secret, 1)]);
        $this->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);
        $this->get('/account')->assertOk();

        $skip = $this->key->assert(skipOptions('remove', $this->spare->id));
        removeWithProof($this->spare, ['factor' => 'passkey', 'credential' => $stepUp])->assertUnprocessable()->assertJsonValidationErrors('proof');

        $this->travel(16)->minutes();
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
        $this->inertia()->get(route('keyring.confirm.challenge', 'passkey'));
        $this->flushHeaders();
        $this->post(route('keyring.confirm.verify', 'passkey'), ['credential' => $skip]);
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));

        expect($this->spare->fresh())->not->toBeNull();
    });

    it('is not lifted by a step-up with the established key', function () {
        $this->travel(16)->minutes();
        $this->get('/account')->assertRedirect(route('keyring.confirm.challenge'));
        $options = $this->inertia()->get(route('keyring.confirm.challenge', 'passkey'))->json('props.challenge.options');
        $this->flushHeaders();
        $this->post(route('keyring.confirm.verify', 'passkey'), ['credential' => $this->key->assert($options)]);
        $this->get('/account')->assertOk();

        $this->deleteJson(route('keyring.authenticators.destroy', $this->spare->id))->assertUnprocessable()->assertJsonPath('frozen.reason', 'new-authenticator');
    });

    it('lets the key remove itself', function () {
        $credential = $this->key->assert(skipOptions('remove', $this->passkey->id));

        removeWithProof($this->passkey, ['factor' => 'passkey', 'credential' => $credential])->assertOk();

        expect($this->passkey->fresh())->toBeNull();
    });

    it('replaces recovery codes with a proof sent when they\'re made', function () {
        $credential = $this->key->assert(skipOptions('replace', 'recovery'));

        $codes = $this->postJson(route('keyring.authenticators.store', 'recovery'), ['proof' => ['factor' => 'passkey', 'credential' => $credential]])
            ->assertOk()
            ->json('enrollment.codes');

        expect($codes)->not->toBeEmpty();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        expect($this->codes->fresh())->toBeNull()
            ->and(SignInChange::query()->count())->toBe(1);
    });

    it('doesn\'t take a challenge for replacing another factor\'s', function () {
        $credential = $this->key->assert(skipOptions('replace', 'totp'));

        $this->postJson(route('keyring.authenticators.store', 'recovery'), ['proof' => ['factor' => 'passkey', 'credential' => $credential]])
            ->assertUnprocessable()
            ->assertJsonValidationErrors('proof');
    });

    it('spends codes begun before the account froze, and takes the proof when they\'re begun again', function () {
        $this->planted->delete();
        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->planted = plantPasskey($this->user);

        // A proof with the confirm counts for nothing: it goes with the beginning.
        $credential = $this->key->assert(skipOptions('replace', 'recovery'));
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'), ['proof' => ['factor' => 'passkey', 'credential' => $credential]])
            ->assertUnprocessable()
            ->assertJsonPath('frozen.skip', ['passkey']);

        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))
            ->assertJsonValidationErrors(['code' => __('keyring::keyring.enrollment_expired')]);

        $credential = $this->key->assert(skipOptions('replace', 'recovery'));
        $this->postJson(route('keyring.authenticators.store', 'recovery'), ['proof' => ['factor' => 'passkey', 'credential' => $credential]])->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        expect($this->codes->fresh())->toBeNull();
    });

    it('doesn\'t let the key it\'s for be newer than "established_after"', function () {
        $this->passkey->forceFill(['created_at' => now()->subDays(6)])->save();
        $this->spare->forceFill(['created_at' => now()->subDays(6)])->save();

        $this->deleteJson(route('keyring.authenticators.destroy', $this->codes->id))->assertJsonPath('frozen.skip', []);

        $this->postJson(route('keyring.authenticators.proof-options', 'passkey'), ['action' => 'remove', 'target' => $this->codes->id])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_not_established')]);

        $credential = $this->key->assert(['challenge' => 'bm90IGEgY2hhbGxlbmdl', 'rpId' => 'localhost']);
        removeWithProof($this->codes, ['factor' => 'passkey', 'credential' => $credential])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
    });

    it('never takes recovery codes or the password', function (array $proof) {
        removeWithProof($this->spare, $proof)
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_not_established')]);

        expect($this->spare->fresh())->not->toBeNull();
    })->with([
        'a recovery code' => [['factor' => 'recovery', 'code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa']],
        'the password' => [['factor' => 'password', 'password' => 'password']],
        'a factor that isn\'t registered' => [['factor' => 'sms', 'code' => '123456']],
    ]);

    it('has no options for a factor that can\'t prove a change', function (string $factor) {
        $this->postJson(route('keyring.authenticators.proof-options', $factor), ['action' => 'remove', 'target' => $this->spare->id])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
    })->with(['totp', 'recovery']);

    it('has no options for a factor that isn\'t registered', function () {
        $this->postJson(route('keyring.authenticators.proof-options', 'sms'), ['action' => 'remove', 'target' => $this->spare->id])->assertNotFound();
    });

    it('checks what the options are asked for', function () {
        $this->postJson(route('keyring.authenticators.proof-options', 'passkey'), ['action' => 'nope', 'target' => ['x']])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['action', 'target']);

        // A rename is for the name it gives, and only a rename has one.
        $this->postJson(route('keyring.authenticators.proof-options', 'passkey'), ['action' => 'rename', 'target' => $this->spare->id])
            ->assertJsonValidationErrors('name');
        $this->postJson(route('keyring.authenticators.proof-options', 'passkey'), ['action' => 'remove', 'target' => $this->spare->id, 'name' => 'Laptop'])
            ->assertJsonValidationErrors('name');
    });

    it('renames an established method with a proof signed for renaming it', function () {
        $this->patchJson(route('keyring.authenticators.update', $this->spare->id), ['name' => 'Laptop'])
            ->assertUnprocessable()
            ->assertJsonPath('frozen.skip', ['passkey']);

        $credential = $this->key->assert(skipOptions('remove', $this->spare->id));
        $this->patchJson(route('keyring.authenticators.update', $this->spare->id), ['name' => 'Laptop', 'proof' => ['factor' => 'passkey', 'credential' => $credential]])
            ->assertJsonValidationErrors('proof');

        // Signed for another name.
        $credential = $this->key->assert(skipOptions('rename', $this->spare->id, name: 'Passkey to remove'));
        $this->patchJson(route('keyring.authenticators.update', $this->spare->id), ['name' => 'Laptop', 'proof' => ['factor' => 'passkey', 'credential' => $credential]])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        $credential = $this->key->assert(skipOptions('rename', $this->spare->id, name: 'Laptop'));
        $this->patchJson(route('keyring.authenticators.update', $this->spare->id), ['name' => 'Laptop', 'proof' => ['factor' => 'passkey', 'credential' => $credential]])
            ->assertOk();

        expect($this->spare->fresh()->name)->toBe('Laptop')
            ->and(SignInChange::query()->count())->toBe(0);
    });

    it('doesn\'t spend a proof on choosing the default', function () {
        $options = skipOptions('rename', $this->spare->id, name: 'Laptop');

        $this->patchJson(route('keyring.authenticators.update', $this->spare->id), ['default' => true, 'proof' => ['factor' => 'passkey', 'credential' => []]])->assertOk();

        expect(session()->has(FreezeSkips::OPTIONS.'.passkey'))->toBeTrue()
            ->and($options)->toHaveKey('challenge');
    });

    it('checks the proof\'s shape', function () {
        $this->deleteJson(route('keyring.authenticators.destroy', $this->spare->id), ['proof' => 'yes'])->assertJsonValidationErrors('proof');
        $this->deleteJson(route('keyring.authenticators.destroy', $this->spare->id), ['proof' => ['code' => '1']])->assertJsonValidationErrors('proof.factor');
    });
});

it('doesn\'t let a key added after the session signed in lift the freeze, however long ago', function () {
    config(['keyring.authenticator_changes.established_after' => '1m']);
    $this->passkey->delete();
    signInForSkip($this->totp);

    $this->travel(1)->minute();
    $key = new VirtualAuthenticator;
    $passkey = Authenticator::factory()->passkey()->for($this->user, 'authenticatable')->create(skipRow($this->user, $key));
    $this->travel(2)->minutes();

    expect($this->user->keyring->refresh()->isEstablished($passkey))->toBeTrue();

    plantPasskey($this->user);

    $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))->assertJsonPath('frozen.skip', []);
    $this->postJson(route('keyring.authenticators.proof-options', 'passkey'), ['action' => 'remove', 'target' => $this->totp->id])
        ->assertJsonValidationErrors('proof');
});

it('says nothing can lift it from a session Keyring never signed in', function () {
    $request = Request::create('/');
    $request->setLaravelSession(session()->driver());

    expect(session()->has(Sessions::KEY))->toBeFalse()
        ->and(app(FreezeSkips::class)->factors($this->user, $request))->toBe([]);
});

it('doesn\'t take a challenge issued for another account', function () {
    signInForSkip($this->totp);
    plantPasskey($this->user);
    $credential = $this->key->assert(skipOptions('remove', $this->totp->id));

    session()->put(FreezeSkips::OPTIONS.'.passkey.user', 'someone:else');

    removeWithProof($this->totp, ['factor' => 'passkey', 'credential' => $credential])->assertUnprocessable()->assertJsonValidationErrors('proof');
    expect($this->totp->fresh())->not->toBeNull();
});

it('names every kind of key that could do it', function () {
    Keyring::factors([Password::class, WebAuthn::passkeys(), WebAuthn::securityKeys(), Totp::class, RecoveryCodes::class]);
    $securityKey = Authenticator::factory()->securityKey()->established()->for($this->user, 'authenticatable')->create();
    plantPasskey($this->user);

    $this->actingAs($this->user)->verifiedWith($securityKey);

    $this->deleteJson(route('keyring.authenticators.destroy', $this->totp->id))->assertJsonPath('frozen.skip', ['passkey', 'security-key']);
});

describe('with an authenticator app', function () {
    beforeEach(function () {
        $this->passkey->delete();
        signInForSkip($this->totp);
        $this->other = Authenticator::factory()->totp()->established()->for($this->user, 'authenticatable')->create();
        plantPasskey($this->user);
    });

    it('can\'t lift it unless the app allows', function () {
        $this->deleteJson(route('keyring.authenticators.destroy', $this->other->id))->assertJsonPath('frozen.skip', []);

        removeWithProof($this->other, ['factor' => 'totp', 'code' => totpCode($this->totp->secret, 1)])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_not_established')]);

        expect($this->other->fresh())->not->toBeNull();
    });

    it('lifts it with a code where the app allows, once per code', function () {
        config(['keyring.authenticator_changes.skip_with_totp' => true]);
        $this->deleteJson(route('keyring.authenticators.destroy', $this->other->id))->assertJsonPath('frozen.skip', ['totp']);

        $code = totpCode($this->totp->secret, 1);
        removeWithProof($this->other, ['factor' => 'totp', 'code' => $code])->assertOk();

        $third = Authenticator::factory()->totp()->established()->for($this->user, 'authenticatable')->create();
        removeWithProof($third, ['factor' => 'totp', 'code' => $code])->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        expect($this->other->fresh())->toBeNull()
            ->and($third->fresh())->not->toBeNull();
    });

    it('checks the app the proof names', function () {
        config(['keyring.authenticator_changes.skip_with_totp' => true]);
        $third = Authenticator::factory()->totp()->established()->for($this->user, 'authenticatable')->create();

        // Without one, a code from the second app is checked against the first.
        removeWithProof($third, ['factor' => 'totp', 'code' => totpCode($this->other->secret, 1)])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        removeWithProof($third, ['factor' => 'totp', 'authenticator' => $this->other->id, 'code' => totpCode($this->other->secret, 1)])->assertOk();

        expect($third->fresh())->toBeNull();
    });

    it('counts a wrong code for the app it names as a failure', function () {
        config(['keyring.authenticator_changes.skip_with_totp' => true]);
        Event::fake([FactorFailed::class]);

        removeWithProof($this->totp, ['factor' => 'totp', 'authenticator' => $this->other->id, 'code' => '000000'])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        Event::assertDispatched(FactorFailed::class, fn (FactorFailed $event) => $event->authenticator?->is($this->other));
    });

    it('won\'t check an app that can\'t prove a change', function (Closure $authenticator) {
        config(['keyring.authenticator_changes.skip_with_totp' => true]);

        removeWithProof($this->other, ['factor' => 'totp', 'authenticator' => $authenticator()->id, 'code' => '000000'])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
    })->with([
        'a newer app' => [fn () => Authenticator::factory()->totp()->for(test()->user, 'authenticatable')->create()],
        'someone else\'s' => [fn () => Authenticator::factory()->totp()->established()->for(taylor(['email' => 'abigail@example.com']), 'authenticatable')->create()],
        'a passkey' => [fn () => Authenticator::factory()->passkey()->established()->for(test()->user, 'authenticatable')->create()],
    ]);

    it('holds wrong codes to the app\'s rate limits', function () {
        config(['keyring.authenticator_changes.skip_with_totp' => true, 'keyring.limits.per_account' => 2]);

        removeWithProof($this->other, ['factor' => 'totp', 'code' => '000000'])->assertUnprocessable();
        removeWithProof($this->other, ['factor' => 'totp', 'code' => '000000'])->assertUnprocessable();
        removeWithProof($this->other, ['factor' => 'totp', 'code' => totpCode($this->totp->secret, 1)])
            ->assertStatus(429)
            ->assertJsonValidationErrors('proof');

        expect($this->other->fresh())->not->toBeNull();
    });

    it('gives back what it counted when the factor fails to check', function () {
        config(['keyring.authenticator_changes.skip_with_totp' => true, 'keyring.limits.consecutive' => 1]);
        Keyring::factors([Password::class, new class(app(Google2FA::class)) extends Totp
        {
            public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
            {
                throw new RuntimeException('Down');
            }
        }, RecoveryCodes::class]);
        $this->withoutExceptionHandling();

        expect(fn () => removeWithProof($this->other, ['factor' => 'totp', 'code' => '000000']))->toThrow(RuntimeException::class, 'Down')
            ->and(fn () => removeWithProof($this->other, ['factor' => 'totp', 'code' => '000000']))->toThrow(RuntimeException::class, 'Down');
    });
});

// A link at an identity provider is a sign-in method like any other: one
// the account has had a while is frozen, and a newer one can always go.
// It never proves a change itself, since it never answers a challenge.
describe('with a link at an identity provider', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, SingleSignOn::class]);
        $this->link = Authenticator::factory()->sso()->established()->for($this->user, 'authenticatable')->create();
        signInForSkip($this->totp);
        plantPasskey($this->user);
    });

    it('unlinks an established one only with a proof from an established key', function () {
        $this->deleteJson(route('keyring.authenticators.destroy', $this->link->id))
            ->assertUnprocessable()
            ->assertJsonPath('frozen.reason', 'new-authenticator')
            ->assertJsonPath('frozen.skip', ['passkey']);
        expect($this->link->fresh())->not->toBeNull();

        removeWithProof($this->link, ['factor' => 'passkey', 'credential' => $this->key->assert(skipOptions('remove', $this->link->id))])->assertOk();

        expect($this->link->fresh())->toBeNull();
    });

    it('unlinks a newer one, frozen or not', function () {
        $newer = Authenticator::factory()->sso(subject: 'someone else')->for($this->user, 'authenticatable')->create();

        $this->deleteJson(route('keyring.authenticators.destroy', $newer->id))->assertOk();
    });

    it('never lets a link prove a change, even one that says it\'s phishing resistant', function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, new class extends SingleSignOn
        {
            public function phishingResistant(Authenticator $authenticator): bool
            {
                return true;
            }
        }]);

        $this->deleteJson(route('keyring.authenticators.destroy', $this->codes->id))->assertJsonPath('frozen.skip', ['passkey']);
        $this->postJson(route('keyring.authenticators.proof-options', 'sso'), ['action' => 'remove', 'target' => $this->codes->id])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_not_established')]);
    });
});

describe('with a phishing resistant factor of the app\'s own', function () {
    beforeEach(function () {
        Keyring::factors([Password::class, WebAuthn::passkeys(), Totp::class, RecoveryCodes::class, SigningToken::class]);
        $this->passkey->delete();
        $this->token = Authenticator::factory()->established()->for($this->user, 'authenticatable')->create(['factor' => 'token', 'name' => 'Token', 'secret' => 'token-secret']);
        signInForSkip($this->totp);
        plantPasskey($this->user);
    });

    it('names it, and makes a change with its answer to a challenge for that change', function () {
        $this->deleteJson(route('keyring.authenticators.destroy', $this->codes->id))->assertJsonPath('frozen.skip', ['token']);

        $nonce = $this->postJson(route('keyring.authenticators.proof-options', 'token'), ['action' => 'remove', 'target' => $this->codes->id])
            ->assertOk()
            ->json('nonce');

        removeWithProof($this->codes, ['factor' => 'token', 'signature' => SigningToken::sign('token-secret', $nonce)])->assertOk();

        expect($this->codes->fresh())->toBeNull()
            ->and($this->token->fresh()->last_used_at)->not->toBeNull();
    });

    it('refuses its answer to a challenge for another change, or none', function () {
        $nonce = $this->postJson(route('keyring.authenticators.proof-options', 'token'), ['action' => 'remove', 'target' => $this->totp->id])->json('nonce');

        removeWithProof($this->codes, ['factor' => 'token', 'signature' => SigningToken::sign('token-secret', $nonce)])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);
        removeWithProof($this->codes, ['factor' => 'token', 'signature' => SigningToken::sign('token-secret', $nonce)])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        expect($this->codes->fresh())->not->toBeNull();
    });

    it('takes its answer once, though the factor would take it again', function () {
        $nonce = $this->postJson(route('keyring.authenticators.proof-options', 'token'), ['action' => 'rename', 'target' => $this->token->id, 'name' => 'Spare'])->json('nonce');
        $earlier = session()->all();
        $proof = ['factor' => 'token', 'signature' => SigningToken::sign('token-secret', $nonce)];

        $this->patchJson(route('keyring.authenticators.update', $this->token->id), ['name' => 'Spare', 'proof' => $proof])->assertOk();
        $this->patchJson(route('keyring.authenticators.update', $this->token->id), ['name' => 'Token'])->assertJsonPath('frozen.skip', ['token']);

        // From a copy of the session that still holds the challenge, as a
        // request sent alongside the first would be.
        sendBackSession($earlier);
        $this->patchJson(route('keyring.authenticators.update', $this->token->id), ['name' => 'Spare', 'proof' => $proof])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);
    });

    it('gives the factor the same attempt it issued the challenge in', function () {
        $this->postJson(route('keyring.authenticators.proof-options', 'token'), ['action' => 'remove', 'target' => $this->codes->id]);
        $id = session(FreezeSkips::OPTIONS.'.token')['nonce'];
        $seen = null;
        Event::listen(FactorFailed::class, function (FactorFailed $event) use (&$seen) {
            $seen = $event->attempt->id;
        });

        removeWithProof($this->codes, ['factor' => 'token', 'signature' => 'nope'])->assertJsonValidationErrors('proof');

        expect($seen)->toBe($id);
    });

    it('refuses a wrong answer as a failure', function () {
        Event::fake([FactorFailed::class]);
        $this->postJson(route('keyring.authenticators.proof-options', 'token'), ['action' => 'remove', 'target' => $this->codes->id]);

        removeWithProof($this->codes, ['factor' => 'token', 'signature' => 'nope'])
            ->assertJsonValidationErrors(['proof' => __('keyring::keyring.freeze_proof_invalid')]);

        Event::assertDispatched(FactorFailed::class, fn (FactorFailed $event) => $event->factor === 'token');
    });

    it('replaces the one a user has with a proof of another method, given when it begins', function () {
        $this->postJson(route('keyring.authenticators.store', 'token'))
            ->assertUnprocessable()
            ->assertJsonPath('frozen.skip', ['token']);

        $nonce = $this->postJson(route('keyring.authenticators.proof-options', 'token'), ['action' => 'replace', 'target' => 'token'])->json('nonce');
        $this->postJson(route('keyring.authenticators.store', 'token'), ['proof' => ['factor' => 'token', 'signature' => SigningToken::sign('token-secret', $nonce)]])->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'token'))->assertOk();

        expect($this->token->fresh())->toBeNull()
            ->and($this->user->keyring->refresh()->of('token'))->toHaveCount(1)
            ->and(SignInChange::query()->count())->toBe(1);
    });
});

describe('the emails about a new sign-in method or new codes', function () {
    beforeEach(function () {
        Notification::fake();
        sendNotifications(['authenticator_added', 'recovery_codes_generated']);
        $this->actingAs($this->user)->verifiedWith($this->totp);
        $this->passkey->delete();
        $this->codes->delete();
    });

    it('link to the app\'s page for sign-in methods, from APP_URL, and say what to do', function () {
        config(['keyring.authenticators_url' => '/settings/security', 'app.url' => 'https://app.example']);

        $this->withHeader('Host', 'evil.example')->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();
        $key = new VirtualAuthenticator;
        $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');
        $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])->assertOk();

        $added = Notification::sent($this->user, AuthenticatorAddedNotice::class)->sole();
        $codes = Notification::sent($this->user, RecoveryCodesGeneratedNotice::class)->sole();

        expect($added->url)->toBe('https://app.example/settings/security')
            ->and($codes->url)->toBe('https://app.example/settings/security');

        $mail = renderedMail($added->toMail($this->user));
        expect($mail['html'])->toContain('href="https://app.example/settings/security"')
            ->and($mail['text'])->toContain('Review your sign-in methods')
            ->toContain('If you didn\'t add it, someone else may be signed in to your account. Remove it, sign out of your account everywhere, and change your password straight away.')
            ->not->toContain('check your sign-in methods straight away');

        $mail = renderedMail($codes->toMail($this->user));
        expect($mail['html'])->toContain('href="https://app.example/settings/security"')
            ->and($mail['text'])->toContain('If you didn\'t make them, someone else may be signed in to your account. Sign out of your account everywhere, change your password, and remove any sign-in method you don\'t recognise straight away.');
    });

    it('keep a full URL as it is', function () {
        config(['keyring.authenticators_url' => 'https://account.example/security']);

        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        expect(Notification::sent($this->user, RecoveryCodesGeneratedNotice::class)->sole()->url)->toBe('https://account.example/security');
    });

    it('have no link without the page, and still say what to do', function () {
        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))->assertOk();

        $codes = Notification::sent($this->user, RecoveryCodesGeneratedNotice::class)->sole();
        $mail = renderedMail($codes->toMail($this->user));

        expect($codes->url)->toBeNull()
            ->and($mail['text'])->not->toContain('Review your sign-in methods')
            ->toContain('If you didn\'t make them');
    });

    it('leave the other notices\' last line as it was', function () {
        $mail = renderedMail(new PasswordChangedNotice(when: 'now')->toMail($this->user));

        expect($mail['text'])->toContain('If this wasn\'t you, change your password and check your sign-in methods straight away.');
    });
});

function signOutForSkip(): void
{
    test()->post('/logout');
    test()->flushSession();
}
