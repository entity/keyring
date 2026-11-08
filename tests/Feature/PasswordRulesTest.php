<?php

use Illuminate\Support\Facades\Validator;
use Keyring\Models\Authenticator;
use Keyring\Support\PasswordRules;

function passes(string $password, mixed ...$arguments): bool
{
    return Validator::make(['password' => $password, 'password_confirmation' => $password], ['password' => PasswordRules::for(...$arguments)])->passes();
}

it('refuses the most common passwords even when the breach check can\'t run', function () {
    config(['keyring.passwords.uncompromised' => false]);

    // With a second factor the minimum is 8, where most common passwords are.
    $user = taylor();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    expect(passes('qz7vbn3k', $user))->toBeTrue()
        ->and(passes('sunshine', $user))->toBeFalse()
        ->and(passes('SunShine', $user))->toBeFalse();
});

it('refuses passwords containing the user\'s name, their email username or the site\'s name', function () {
    config(['app.name' => 'Keyring Example']);
    $user = taylor(['name' => 'Taylor Otwell', 'email' => 'tayotw@example.com']);

    expect(passes('a long passphrase for me', $user))->toBeTrue()
        ->and(passes('otwell is my long passphrase', $user))->toBeFalse()
        ->and(passes('my long passphrase tayotw', $user))->toBeFalse()
        ->and(passes('keyring was here for ages', $user))->toBeFalse();
});

it('checks the words it\'s given before there\'s a user, ignoring short ones', function () {
    expect(passes('jordan rivers long phrase', context: ['Jordan Rivers', 'jr@example.com']))->toBeFalse()
        ->and(passes('a long passphrase with jr in it', context: ['Jo', 'jr@example.com']))->toBeTrue();
});
