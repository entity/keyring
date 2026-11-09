<?php

use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;

function verified(string $factor, array $categories, bool $phishingResistant = false, bool $deviceBound = false): Verification
{
    return new Verification($factor, null, $categories, $phishingResistant, time(), $deviceBound);
}

it('counts distinct categories, not verifications', function () {
    $password = verified('password', [Category::Knowledge]);
    $pin = verified('pin', [Category::Knowledge]);
    $totp = verified('totp', [Category::Possession]);

    expect(Requirement::aal2()->isMetBy([$password, $pin]))->toBeFalse()
        ->and(Requirement::aal2()->isMetBy([$password, $totp]))->toBeTrue()
        ->and(Requirement::aal1()->isMetBy([$password]))->toBeTrue()
        ->and(Requirement::aal1()->isMetBy([]))->toBeFalse();
});

it('lets a user verified passkey finish aal2 on its own, and aal3 only when it can\'t sync', function () {
    $synced = verified('webauthn', [Category::Possession, Category::Inherence], phishingResistant: true);
    $bound = verified('webauthn', [Category::Possession, Category::Inherence], phishingResistant: true, deviceBound: true);

    expect(Requirement::aal2()->isMetBy([$synced]))->toBeTrue()
        ->and(Requirement::aal3()->isMetBy([$synced]))->toBeFalse()
        ->and(Requirement::aal3()->isMetBy([$bound]))->toBeTrue()
        ->and(Requirement::aal3()->wouldProgress([], $synced))->toBeFalse()
        ->and(Requirement::aal3()->wouldProgress([], $bound))->toBeTrue();
});

it('requires specific categories', function () {
    $password = verified('password', [Category::Knowledge]);
    $email = verified('email-code', [Category::Possession]);
    $requirement = Requirement::aal2()->including(Category::Possession);

    expect($requirement->isMetBy([$password]))->toBeFalse()
        ->and($requirement->isMetBy([$password, $email]))->toBeTrue();
});

it('requires a phishing resistant verification', function () {
    $password = verified('password', [Category::Knowledge]);
    $totp = verified('totp', [Category::Possession]);
    $key = verified('webauthn', [Category::Possession], phishingResistant: true);
    $requirement = Requirement::aal2()->phishingResistant();

    expect($requirement->isMetBy([$password, $totp]))->toBeFalse()
        ->and($requirement->isMetBy([$password, $key]))->toBeTrue();
});

it('knows whether another verification would help', function () {
    $password = verified('password', [Category::Knowledge]);

    expect(Requirement::aal2()->wouldProgress([$password], verified('pin', [Category::Knowledge])))->toBeFalse()
        ->and(Requirement::aal2()->wouldProgress([$password], verified('totp', [Category::Possession])))->toBeTrue()
        ->and(Requirement::aal2()->phishingResistant()->wouldProgress([$password], verified('totp', [Category::Possession])))->toBeFalse()
        ->and(Requirement::aal2()->phishingResistant()->wouldProgress([$password], verified('webauthn', [Category::Possession], phishingResistant: true)))->toBeTrue();
});

it('limits itself to what a user can prove', function () {
    $can = [Category::Knowledge, Category::Possession];

    expect(Requirement::aal3()->limitedTo($can, false))
        ->factors->toBe(2)
        ->categories->toBe([Category::Possession])
        ->requiresPhishingResistance->toBeFalse()
        ->and(Requirement::factors(3)->phishingResistant()->limitedTo($can, true))
        ->factors->toBe(2)
        ->requiresPhishingResistance->toBeTrue()
        ->and(Requirement::aal1()->phishingResistant()->limitedTo($can, false)->factors)->toBe(2)
        ->and(Requirement::aal2()->including(Category::Possession)->limitedTo([Category::Knowledge], false))
        ->factors->toBe(1)
        ->categories->toBe([]);
});

it('round trips through an array', function () {
    $requirement = Requirement::aal2()->including(Category::Possession)->phishingResistant()->ifEnrolled();

    expect(Requirement::fromArray($requirement->toArray()))->toEqual($requirement);
});

it('keeps refusing recovery codes through storage and when combined', function () {
    $refusing = Requirement::aal1()->withoutRecoveryCodes();

    expect(Requirement::fromArray($refusing->toArray()))->toEqual($refusing)
        ->and(Requirement::aal2()->atLeast($refusing)->acceptsRecoveryCodes)->toBeFalse()
        ->and(Requirement::aal2()->atLeast(Requirement::aal1())->acceptsRecoveryCodes)->toBeTrue();
});

it('works out assurance from verifications', function () {
    $password = verified('password', [Category::Knowledge]);
    $totp = verified('totp', [Category::Possession]);
    $synced = verified('webauthn', [Category::Possession], phishingResistant: true);
    $key = verified('webauthn', [Category::Possession], phishingResistant: true, deviceBound: true);

    expect(Assurance::of([]))->toBe(Assurance::None)
        ->and(Assurance::of([$password]))->toBe(Assurance::AAL1)
        ->and(Assurance::of([$password, $totp]))->toBe(Assurance::AAL2)
        ->and(Assurance::of([$password, $synced]))->toBe(Assurance::AAL2)
        ->and(Assurance::of([$password, $key]))->toBe(Assurance::AAL3);
});

it('reads assurance levels from middleware parameters in any case', function () {
    expect(Assurance::fromName('none'))->toBe(Assurance::None)
        ->and(Assurance::fromName('aal3'))->toBe(Assurance::AAL3)
        ->and(fn () => Assurance::fromName('aal4'))->toThrow(InvalidArgumentException::class, 'Unknown assurance level [aal4].');
});
