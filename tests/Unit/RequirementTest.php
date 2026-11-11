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
    $sms = verified('sms', [Category::Possession]);
    $requirement = Requirement::aal2()->including(Category::Possession);

    expect($requirement->isMetBy([$password]))->toBeFalse()
        ->and($requirement->isMetBy([$password, $sms]))->toBeTrue();
});

it('doesn\'t count a code sent to an address as a factor', function () {
    $password = verified('password', [Category::Knowledge]);
    $email = verified('email-code', [Category::Address]);
    $totp = verified('totp', [Category::Possession]);

    expect(Category::Address->authenticates())->toBeFalse()
        ->and(Requirement::aal2()->isMetBy([$password, $email]))->toBeFalse()
        ->and(Requirement::aal2()->including(Category::Possession)->isMetBy([$password, $email]))->toBeFalse()
        ->and(Requirement::aal1()->isMetBy([$email]))->toBeFalse()
        ->and(Requirement::aal2()->wouldProgress([$password], $email))->toBeFalse()
        ->and(Assurance::of([$password, $email]))->toBe(Assurance::AAL1)
        ->and(Assurance::of([$email]))->toBe(Assurance::None)
        ->and(Assurance::of([$password, $email, $totp]))->toBe(Assurance::AAL2);
});

it('counts a code sent to an address as a step where steps are asked for', function () {
    $password = verified('password', [Category::Knowledge]);
    $pin = verified('pin', [Category::Knowledge]);
    $email = verified('email-code', [Category::Address]);
    $totp = verified('totp', [Category::Possession]);
    $steps = Requirement::steps(2);

    expect($steps->isMetBy([$password]))->toBeFalse()
        ->and($steps->isMetBy([$password, $pin]))->toBeFalse()
        ->and($steps->isMetBy([$password, $email]))->toBeTrue()
        ->and($steps->isMetBy([$password, $totp]))->toBeTrue()
        ->and($steps->isMetBy([$email]))->toBeFalse()
        ->and($steps->wouldProgress([$password], $email))->toBeTrue()
        ->and($steps->wouldProgress([$password], $totp))->toBeTrue()
        ->and($steps->wouldProgress([$password], $pin))->toBeFalse()
        ->and($steps->wouldProgress([$password, $email], $totp))->toBeFalse()
        ->and(Requirement::fromArray($steps->toArray()))->toEqual($steps);
});

it('asks for the step a user has when they can\'t give a second factor', function () {
    $password = verified('password', [Category::Knowledge]);
    $email = verified('email-code', [Category::Address]);
    $totp = verified('totp', [Category::Possession]);

    expect(Requirement::aal2()->limitedTo([$password, $email]))
        ->factors->toBe(1)
        ->steps->toBe(2)
        ->and(Requirement::aal2()->limitedTo([$password, $email])->isMetBy([$password]))->toBeFalse()
        ->and(Requirement::aal2()->limitedTo([$password, $email])->isMetBy([$password, $email]))->toBeTrue()
        ->and(Requirement::aal2()->phishingResistant()->limitedTo([$password, $totp, $email]))
        ->factors->toBe(2)
        ->steps->toBe(0)
        ->and(Requirement::aal2()->limitedTo([$password])->steps)->toBe(0);
});

it('keeps the most steps when two requirements are combined', function () {
    $password = verified('password', [Category::Knowledge]);
    $email = verified('email-code', [Category::Address]);
    $totp = verified('totp', [Category::Possession]);

    // One factor, and a second step of any kind.
    $either = Requirement::aal1()->atLeast(Requirement::steps(2));

    expect($either->isMetBy([$password, $email]))->toBeTrue()
        ->and($either->isMetBy([$password]))->toBeFalse()
        ->and(Requirement::steps(2)->atLeast(Requirement::aal2())->isMetBy([$password, $email]))->toBeFalse()
        ->and(Requirement::steps(2)->atLeast(Requirement::aal2())->isMetBy([$password, $totp]))->toBeTrue()
        ->and(Requirement::steps(2)->atLeast(Requirement::aal2())->wouldProgress([$password], $email))->toBeFalse();
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
    $password = verified('password', [Category::Knowledge]);
    $totp = verified('totp', [Category::Possession]);
    $key = verified('webauthn', [Category::Possession], phishingResistant: true);

    expect(Requirement::aal3()->limitedTo([$password, $totp]))
        ->factors->toBe(2)
        ->categories->toBe([Category::Possession])
        ->requiresPhishingResistance->toBeFalse()
        ->and(Requirement::factors(3)->phishingResistant()->limitedTo([$password, $key]))
        ->factors->toBe(2)
        ->requiresPhishingResistance->toBeTrue()
        ->and(Requirement::aal1()->phishingResistant()->limitedTo([$password, $totp])->factors)->toBe(2)
        ->and(Requirement::aal2()->including(Category::Possession)->limitedTo([$password]))
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
