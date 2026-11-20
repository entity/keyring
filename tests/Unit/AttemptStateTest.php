<?php

declare(strict_types=1);

use Keyring\Enums\Purpose;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;

it('has nothing to offer before it knows what it needs', function () {
    $user = taylor();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $attempt = Attempt::start(Purpose::Login, $user);

    expect($attempt->options())->toBeEmpty()
        ->and($attempt->complete)->toBeFalse();

    $attempt->requirement = Requirement::aal2();

    expect($attempt->options()->pluck('factor')->all())->toContain('totp');
});

it('forgets one piece of a factor\'s state, or all of it', function () {
    $attempt = Attempt::start(Purpose::Login, taylor());
    $attempt->put('voice', 'phrase', 'my voice is my passport');
    $attempt->put('voice', 'tries', 2);
    $attempt->put('totp', 'shown', true);

    $attempt->forget('voice', 'tries');

    expect($attempt->state('voice'))->toBe(['phrase' => 'my voice is my passport'])
        ->and($attempt->state('voice', 'tries', 0))->toBe(0);

    $attempt->forget('voice');

    expect($attempt->state('voice'))->toBe([])
        ->and($attempt->state('totp', 'shown'))->toBeTrue();

    // What's left is what the session keeps.
    expect(Attempt::fromArray($attempt->toArray())->state)->toBe(['totp' => ['shown' => true]]);
});
