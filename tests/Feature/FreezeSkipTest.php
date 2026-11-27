<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Keyring\Changes\AuthenticatorChanges;
use Keyring\Changes\FreezeSkips;
use Keyring\Enums\FreezeReason;
use Keyring\Events\FactorFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Models\SignInChange;
use Keyring\Sessions\Sessions;
use Keyring\Testing\VirtualAuthenticator;
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
function skipOptions(string $action, string $target, string $factor = 'passkey'): array
{
    return test()->postJson(route('keyring.authenticators.proof-options', $factor), ['action' => $action, 'target' => $target])
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

    it('takes the proof with the confirm, for codes begun before the account froze', function () {
        $this->planted->delete();
        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->planted = plantPasskey($this->user);

        $this->postJson(route('keyring.authenticators.confirm', 'recovery'))
            ->assertUnprocessable()
            ->assertJsonPath('frozen.skip', ['passkey']);

        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertUnprocessable();
        $this->planted->delete();
        $this->postJson(route('keyring.authenticators.store', 'recovery'))->assertOk();
        $this->planted = plantPasskey($this->user);

        $credential = $this->key->assert(skipOptions('replace', 'recovery'));
        $this->postJson(route('keyring.authenticators.confirm', 'recovery'), ['proof' => ['factor' => 'passkey', 'credential' => $credential]])->assertOk();

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

    it('has no options for a factor that isn\'t a key', function (string $factor) {
        $this->postJson(route('keyring.authenticators.proof-options', $factor), ['action' => 'remove', 'target' => $this->spare->id])->assertNotFound();
    })->with(['totp', 'recovery', 'sms']);

    it('checks what the options are asked for', function () {
        $this->postJson(route('keyring.authenticators.proof-options', 'passkey'), ['action' => 'rename', 'target' => ['x']])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(['action', 'target']);
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

function signOutForSkip(): void
{
    test()->post('/logout');
    test()->flushSession();
}
