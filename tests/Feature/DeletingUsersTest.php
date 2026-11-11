<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Keyring\Contracts\SessionRegistry;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Assurance;
use Keyring\Models\Authenticator;
use Keyring\Models\Device;
use Keyring\Models\PendingChange;
use Keyring\Models\SecurityEvent;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Tests\Fixtures\SoftDeletingUser;
use Keyring\Tests\Fixtures\User;

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

it('does not let an old remember me cookie back in once a soft deleted user is restored', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    config(['auth.providers.users.model' => SoftDeletingUser::class]);
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password', 'remember' => true]);
    $user = $user->fresh();
    $remembered = [Auth::guard()->getRecallerName() => $user->id.'|'.$user->remember_token.'|'.$user->password];

    $user->delete();
    $user->restore();
    $this->flushSession();
    Auth::forgetGuards();

    $this->withCookies($remembered)->get('/home')->assertRedirect('/login');
});

it('signs a soft deleted user out but keeps their sign-in methods', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password']);
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
    $session = new RegisteredSession('kept', (string) $user->id, RegisteredSession::typeOf($user), 'web', null, Assurance::AAL1, null, null, 0, 0, now()->addHour()->getTimestamp());
    app(SessionRegistry::class)->save($session);

    $user->delete();

    // Signed out at once, but the sign-in methods stay in case of a restore.
    expect(app(SessionRegistry::class)->find('kept')->revokedAt)->not->toBeNull()
        ->and(Authenticator::count())->toBe(1);

    $user->forceDelete();
    expect(Authenticator::count())->toBe(0);
});

// The "this wasn't me" link of a change that was applied before the account
// was deactivated. Whoever changed the address may be why it was.
function appliedEmailChange(SoftDeletingUser $user): PendingChange
{
    $change = new PendingChange([
        'attribute' => 'email',
        'value' => 'new@example.com',
        'previous_value' => 'taylor@example.com',
        'confirm_token' => PendingChange::hashToken('confirm'),
        'revert_token' => PendingChange::hashToken('revert'),
        'confirmed_at' => now(),
        'applied_at' => now(),
        'revertable_until' => now()->addDays(7),
        'expires_at' => now()->addDay(),
    ]);

    return tap($change, fn (PendingChange $change) => $change->authenticatable()->associate($user)->save());
}

it('still undoes an email change for a soft deleted user, ready for when they are restored', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    config(['auth.providers.users.model' => SoftDeletingUser::class]);
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'new@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    $change = appliedEmailChange($user);
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $user->delete();

    $this->post(route('keyring.email.revert.store', $change->id), ['token' => 'revert'])->assertSessionHas('status', 'email-change-reverted');

    $user->restore();

    expect($user->fresh()->email)->toBe('taylor@example.com')
        ->and(Authenticator::count())->toBe(0)
        ->and($change->fresh()->reverted_at)->not->toBeNull();
});

it('does not use up the link when there is no account left to put the address back on', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    config(['auth.providers.users.model' => SoftDeletingUser::class]);
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'new@example.com', 'password' => 'password', 'email_verified_at' => now()]);
    $change = appliedEmailChange($user);

    // Removed without the model knowing, so Keyring's records are still there.
    DB::table('users')->where('id', $user->id)->delete();

    $this->post(route('keyring.email.revert.store', $change->id), ['token' => 'revert'])->assertSessionHas('status', 'email-change-invalid');

    expect($change->fresh()->reverted_at)->toBeNull();
});

it('signs a reported device out for a soft deleted user too, so a restore does not bring its session back', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    config(['auth.providers.users.model' => SoftDeletingUser::class]);
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $session = session(Sessions::KEY);
    $device = Device::sole();

    // Deactivated without the model knowing, so nothing signed them out.
    DB::table('users')->where('id', $user->id)->update(['deleted_at' => now()]);

    app(DeviceManager::class)->revoke($device, reported: true);

    expect(app(SessionRegistry::class)->find($session)->revokedAt)->not->toBeNull();
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

it('deletes a user\'s security log entries with them, and nobody else\'s', function () {
    $user = taylor();
    $other = User::create(['name' => 'Abigail', 'email' => 'abigail@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    $this->withHeader('User-Agent', FIREFOX)->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    $this->post('/login', ['email' => 'abigail@example.com', 'password' => 'wrong']);
    $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'wrong']);

    expect(SecurityEvent::query()->ownedBy($user)->sole())->ip->toBe('127.0.0.1')->user_agent->toBe(FIREFOX);

    $user->delete();

    expect(SecurityEvent::query()->ownedBy($user)->count())->toBe(0)
        ->and(SecurityEvent::query()->ownedBy($other)->count())->toBe(1)
        ->and(SecurityEvent::query()->whereNull('authenticatable_id')->count())->toBe(1);
});

it('keeps a soft deleted user\'s security log entries, in case they are restored', function () {
    Schema::table('users', fn (Blueprint $table) => $table->softDeletes());
    config(['auth.providers.users.model' => SoftDeletingUser::class]);
    $user = SoftDeletingUser::create(['name' => 'Taylor', 'email' => 'taylor@example.com', 'password' => 'password', 'email_verified_at' => now()]);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);

    $user->delete();
    expect(SecurityEvent::query()->ownedBy($user)->count())->toBe(1);

    $user->forceDelete();
    expect(SecurityEvent::query()->ownedBy($user)->count())->toBe(0);
});
