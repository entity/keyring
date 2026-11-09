<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Schema;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\SoftDeletingUser;

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

it('signs a soft deleted user out but keeps their sign-in methods', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
    $session = new RegisteredSession('kept', (string) $user->id, 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp());
    app(SessionRegistry::class)->save($session);

    $user->delete();

    // Signed out at once, but the sign-in methods stay in case of a restore.
    expect(app(SessionRegistry::class)->find('kept')->revokedAt)->not->toBeNull()
        ->and(Authenticator::count())->toBe(1);

    $user->forceDelete();
    expect(Authenticator::count())->toBe(0);
});

it('ends the user\'s reset links with them, so whoever registers the address next can\'t be reset with one', function () {
    $user = taylor();
    $token = Password::broker()->createToken($user);

    $user->delete();

    $next = taylor(['password' => 'a different passphrase']);
    expect(Password::broker()->tokenExists($next, $token))->toBeFalse();

    $this->post(route('password.update'), ['token' => $token, 'email' => 'taylor@example.com', 'password' => 'attacker set passphrase', 'password_confirmation' => 'attacker set passphrase'])
        ->assertSessionHasErrors('email');
    expect(Hash::check('a different passphrase', $next->fresh()->password))->toBeTrue();
});

it('ends a soft deleted user\'s reset links, so a restore does not bring them back', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
    $token = Password::broker()->createToken($user);

    $user->delete();
    $user->restore();

    expect(Password::broker()->tokenExists($user->fresh(), $token))->toBeFalse();
});
