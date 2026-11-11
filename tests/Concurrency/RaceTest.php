<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Models\FailureCount;
use Keyring\Models\PendingChange;
use Keyring\Sessions\RegisteredSession;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\WebAuthn\Ceremonies;
use Keyring\WebAuthn\Profile;
use ParagonIE\ConstantTime\Base64UrlSafe;
use Webauthn\AuthenticatorSelectionCriteria;

beforeEach(function () {
    if (DB::getDriverName() === 'sqlite') {
        $this->markTestSkipped('SQLite has no row locks; CI runs these on PostgreSQL and MySQL.');
    }

    useRaceFactors();
});

it('never lets two removals at once take the last way in', function () {
    $user = taylor(['password' => null]);
    $first = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create();
    $second = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create();

    $results = contend($user, [
        ['remove-authenticator', $user->id, $first->id],
        ['remove-authenticator', $user->id, $second->id],
    ]);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, 'refused'))->toBe(1)
        ->and(Authenticator::query()->where('factor', 'passkey')->count())->toBe(1);
});

it('spends a recovery code once, however many requests bring it', function () {
    $user = taylor();
    $codes = Authenticator::factory()->recoveryCodes(['aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa', 'bbbb-bbbb-bbbb-bbbb-bbbb-bbbb-bb'])->for($user, 'authenticatable')->create();

    $results = contend($codes, [
        ['use-recovery-code', $codes->id, 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'],
        ['use-recovery-code', $codes->id, 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'],
    ]);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, false))->toBe(1);
});

it('lets one of two assertions with the same count through, and keeps that count', function () {
    $user = taylor();
    $ceremonies = app(Ceremonies::class);
    $key = new VirtualAuthenticator;

    $creation = $ceremonies->creationOptions($user, Profile::passkeys(), []);
    $record = $ceremonies->register(json_encode($key->register($ceremonies->toBrowser($creation))), $ceremonies->toJson($creation), Profile::passkeys());

    $passkey = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create([
        'credential_id' => Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId),
        'public_key' => $ceremonies->toJson($record),
        'sign_count' => $record->counter,
    ]);

    $options = $ceremonies->requestOptions([], AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED);
    $browser = $ceremonies->toBrowser($options);
    $json = $ceremonies->toJson($options);

    // A clone answers with the same counter as the original.
    $results = contend($passkey, [
        ['use-passkey', $passkey->id, (string) json_encode(['options' => $json, 'credential' => (clone $key)->assert($browser)])],
        ['use-passkey', $passkey->id, (string) json_encode(['options' => $json, 'credential' => (clone $key)->assert($browser)])],
    ]);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, false))->toBe(1)
        ->and($passkey->fresh()->sign_count)->toBe($record->counter + 1);
});

it('checks one more proof at the last failure the cap allows, however many arrive together', function () {
    $user = taylor();

    // One short of the 80 failures in a row browsers the account hasn't
    // signed in from may make.
    $count = new FailureCount(['factor' => 'password', 'authenticator' => 'password', 'failures' => 79]);
    $count->authenticatable()->associate($user)->save();

    $results = contend($count, [
        ['guess-password', $user->id],
        ['guess-password', $user->id],
        ['guess-password', $user->id],
    ]);

    expect(outcomes($results, 'checked'))->toBe(1)
        ->and(outcomes($results, 'refused'))->toBe(2)
        ->and($count->fresh())
        ->failures->toBe(80)
        ->locked_at->not->toBeNull();
});

it('ends with the old address whichever of confirm and revert wins', function () {
    $user = taylor();
    $change = new PendingChange([
        'attribute' => 'email',
        'value' => 'new@example.com',
        'previous_value' => 'taylor@example.com',
        'confirm_token' => PendingChange::hashToken('confirm'),
        'revert_token' => PendingChange::hashToken('revert'),
        'expires_at' => now()->addDay(),
    ]);
    $change->authenticatable()->associate($user)->save();

    [$confirmed, $reverted] = contend($change, [
        ['confirm-email-change', $change->id, 'confirm'],
        ['revert-email-change', $change->id, 'revert'],
    ]);

    // Confirming first applies the change and the revert undoes it; reverting
    // first leaves nothing to confirm.
    expect($confirmed)->toBeIn(['Applied', 'Invalid'])
        ->and($reverted)->toBeTrue()
        ->and($user->fresh()->email)->toBe('taylor@example.com')
        ->and($change->fresh()->reverted_at)->not->toBeNull();
});

it('puts the address back when a later change is confirmed while an earlier one is being reverted', function () {
    $user = taylor();
    $pending = fn (string $address) => tap(new PendingChange([
        'attribute' => 'email',
        'value' => $address,
        'previous_value' => 'taylor@example.com',
        'confirm_token' => PendingChange::hashToken('confirm'),
        'revert_token' => PendingChange::hashToken('revert'),
        'expires_at' => now()->addDay(),
    ]), fn (PendingChange $change) => $change->authenticatable()->associate($user)->save());

    // Asked for and then replaced by a second request: its "this wasn't me"
    // link still works.
    $first = $pending('first@example.com');
    $first->forceFill(['cancelled_at' => now(), 'revertable_until' => now()->addDay()])->save();
    $second = $pending('second@example.com');

    // The second change's confirmation holds its row. The revert waits for
    // it, and the confirmation finishes before letting go.
    [$reverted] = contend($second, [['revert-email-change', $first->id, 'revert']], function () use ($user, $second) {
        Keyring::withoutProtection(fn () => $user->forceFill(['email' => 'second@example.com'])->save());
        $second->forceFill(['confirmed_at' => now(), 'applied_at' => now(), 'revertable_until' => now()->addDay()])->save();
    });

    expect($reverted)->toBeTrue()
        ->and($user->fresh()->email)->toBe('taylor@example.com')
        ->and($second->fresh()->canRevert())->toBeFalse();
});

it('lets one of two requests use a "remember me" cookie, and starts one session between them', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('remembered', (string) $user->id, 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600));

    // Both read the record before either can replace it.
    $results = contend(sessionRow('remembered'), [
        ['resume-session', 'remembered'],
        ['resume-session', 'remembered'],
    ]);

    // The one that lost is told so, and joins the other's session (the
    // middleware looks the record up again).
    $resumed = $registry->find('remembered')->replacedBy;

    expect(outcomes($results, null))->toBe(1)
        ->and(outcomes($results, $resumed))->toBe(1)
        ->and($registry->forUser($user)->map->id->all())->toBe([$resumed])
        ->and(DB::table('keyring_sessions')->count())->toBe(2);
});
