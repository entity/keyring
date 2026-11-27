<?php

declare(strict_types=1);

use Keyring\Enums\Category;
use Keyring\Login\Verification;

it('keeps what an identity provider said through the session', function () {
    $verification = new Verification('sso', 'link', [Category::Knowledge], at: 1_700_000_000, authenticatedAt: 1_699_990_000, providerAmr: ['pwd', 'mfa'], providerAcr: 'urn:example:silver');

    expect($verification->toArray())->toMatchArray(['provider_amr' => ['pwd', 'mfa'], 'provider_acr' => 'urn:example:silver'])
        ->and(Verification::fromArray($verification->toArray()))->toEqual($verification);
});

it('loads one saved before the provider\'s claims were kept', function () {
    $verification = Verification::fromArray(['factor' => 'sso', 'authenticator' => 'link', 'categories' => ['knowledge'], 'at' => 1_700_000_000]);

    expect($verification->providerAmr)->toBe([])
        ->and($verification->providerAcr)->toBeNull()
        ->and($verification->toArray())->not->toHaveKeys(['provider_amr', 'provider_acr']);
});

it('says when it was proved only when that is known', function (?int $authenticatedAt, ?int $known) {
    $verification = new Verification('sso', 'link', [Category::Knowledge], at: 1_700_000_000, authenticatedAt: $authenticatedAt);

    expect($verification->provedAtIfKnown())->toBe($known)
        ->and($verification->provedAt())->toBe($known ?? Verification::UNKNOWN);
})->with([
    'as checked' => [null, 1_700_000_000],
    'earlier' => [1_699_990_000, 1_699_990_000],
    'unknown' => [Verification::UNKNOWN, null],
]);
