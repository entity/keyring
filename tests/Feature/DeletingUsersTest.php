<?php

use Keyring\Contracts\SessionRegistry;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Sessions\Sessions;

it('removes sign-in methods, devices, pending changes and sessions with the user', function () {
    $user = taylor();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => totpCode($user->authenticators()->first()->secret)]);
    $session = session(Sessions::KEY);
    $this->post(route('keyring.email.store'), ['email' => 'new@example.com']);

    expect(Device::count())->toBe(1)->and(PendingChange::count())->toBe(1);

    $user->delete();

    expect(Authenticator::count())->toBe(0)
        ->and(Device::count())->toBe(0)
        ->and(PendingChange::count())->toBe(0)
        ->and(app(SessionRegistry::class)->find($session)?->revokedAt)->not->toBeNull();
});
