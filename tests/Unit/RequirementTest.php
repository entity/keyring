<?php

use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Login\Requirement;
use Keyring\Login\Verification;

function verified(string $factor, array $categories, bool $phishingResistant = false): Verification
{
    return new Verification($factor, null, $categories, $phishingResistant, time());
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

it('lets a user verified passkey finish aal2 on its own', function () {
    $passkey = verified('webauthn', [Category::Possession, Category::Inherence], phishingResistant: true);

    expect(Requirement::aal2()->isMetBy([$passkey]))->toBeTrue()
        ->and(Requirement::aal3()->isMetBy([$passkey]))->toBeTrue();
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

    expect(Requirement::aal2()->wouldProgress([$password], [Category::Knowledge], false))->toBeFalse()
        ->and(Requirement::aal2()->wouldProgress([$password], [Category::Possession], false))->toBeTrue()
        ->and(Requirement::aal2()->phishingResistant()->wouldProgress([$password], [Category::Possession], false))->toBeFalse()
        ->and(Requirement::aal2()->phishingResistant()->wouldProgress([$password], [Category::Possession], true))->toBeTrue();
});

it('round trips through an array', function () {
    $requirement = Requirement::aal2()->including(Category::Possession)->phishingResistant()->ifEnrolled();

    expect(Requirement::fromArray($requirement->toArray()))->toEqual($requirement);
});

it('works out assurance from verifications', function () {
    $password = verified('password', [Category::Knowledge]);
    $totp = verified('totp', [Category::Possession]);
    $key = verified('webauthn', [Category::Possession], phishingResistant: true);

    expect(Assurance::of([]))->toBe(Assurance::None)
        ->and(Assurance::of([$password]))->toBe(Assurance::AAL1)
        ->and(Assurance::of([$password, $totp]))->toBe(Assurance::AAL2)
        ->and(Assurance::of([$password, $key]))->toBe(Assurance::AAL3);
});

it('reads assurance levels from middleware parameters in any case', function () {
    expect(Assurance::fromName('none'))->toBe(Assurance::None)
        ->and(Assurance::fromName('aal3'))->toBe(Assurance::AAL3)
        ->and(fn () => Assurance::fromName('aal4'))->toThrow(InvalidArgumentException::class, 'Unknown assurance level [aal4].');
});
