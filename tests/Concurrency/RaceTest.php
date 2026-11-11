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

it('takes one of two answers to the same challenge, though the passkey\'s count never moves', function () {
    $user = taylor();
    $ceremonies = app(Ceremonies::class);
    // A synced passkey: its count stays at zero, so only the challenge
    // tells a second use of an answer from the first.
    $key = new VirtualAuthenticator(synced: true, counts: false);

    $creation = $ceremonies->creationOptions($user, Profile::passkeys(), []);
    $record = $ceremonies->register(json_encode($key->register($ceremonies->toBrowser($creation))), $ceremonies->toJson($creation), Profile::passkeys());

    $passkey = Authenticator::factory()->passkey()->for($user, 'authenticatable')->create([
        'credential_id' => Base64UrlSafe::encodeUnpadded($record->publicKeyCredentialId),
        'public_key' => $ceremonies->toJson($record),
        'sign_count' => $record->counter,
    ]);

    $options = $ceremonies->requestOptions([], AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED);
    $answer = (string) json_encode(['options' => $ceremonies->toJson($options), 'credential' => $key->assert($ceremonies->toBrowser($options))]);

    // The same signed answer, twice. One uses the challenge up and goes on
    // to wait for the key's row. The other is turned away before it.
    $results = contend($passkey, [
        ['answer-challenge', $passkey->id, $answer],
        ['answer-challenge', $passkey->id, $answer],
    ], waiting: 1);

    expect(outcomes($results, true))->toBe(1)
        ->and(outcomes($results, false))->toBe(1)
        ->and($passkey->fresh()->sign_count)->toBe(0);
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

it('keeps an account to its session limit when two sign ins land at once', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);

    foreach (['older' => 120, 'newer' => 60] as $id => $ago) {
        $registry->save(new RegisteredSession($id, (string) $user->id, 'web', null, Assurance::AAL1, null, null, $now - $ago, $now - $ago, $now + 3600));
    }

    // Each waits for the user's row, so the second counts the first's session.
    $started = contend($user, [
        ['start-session', $user->id, 2],
        ['start-session', $user->id, 2],
    ]);

    expect($registry->forUser($user)->map->id->all())->toEqualCanonicalizing($started)
        ->and($registry->find('older')->revokedAt)->not->toBeNull()
        ->and($registry->find('newer')->revokedAt)->not->toBeNull();
});

it('leaves nothing signed in when a sign-out everywhere meets a "remember me" cookie coming back', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save(new RegisteredSession('remembered', (string) $user->id, 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600, remembered: true));

    // Both wait for the user's row. Whichever goes first, the session ends:
    // signed out and then refused, or carried on and then signed out.
    [$resumed, $revoked] = contend($user, [
        ['resume-session', 'remembered'],
        ['sign-out', $user->id],
    ]);

    expect($revoked)->toBe(1)
        ->and($registry->forUser($user))->toBeEmpty()
        ->and($registry->find($resumed ?? 'remembered')->revokedAt)->not->toBeNull();
});

it('signs out a session that moved to a new record while everyone was being signed out', function () {
    $user = taylor();
    $now = now()->getTimestamp();
    $registry = app(SessionRegistry::class);
    $registry->save($session = new RegisteredSession('remembered', (string) $user->id, 'web', null, Assurance::AAL1, null, null, $now, $now, $now + 3600, remembered: true));

    // The sign-out comes to the record while "remember me" is carrying its
    // session on, and waits. By the time it gets the record, the session is
    // on another one it hasn't seen.
    contend(sessionRow('remembered'), [['sign-out-everyone', 'everyone']], function () use ($registry, $session) {
        expect($registry->replace('remembered', $session->with(['id' => 'resumed'])))->toBeTrue();
    });

    expect($registry->find('resumed')->revokedAt)->not->toBeNull()
        ->and($registry->find('remembered')->revokedAt)->not->toBeNull()
        ->and($registry->forUser($user))->toBeEmpty();
});
