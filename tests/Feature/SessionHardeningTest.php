<?php

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\SessionRegistry;
use Keyring\Contracts\Signal;
use Keyring\Facades\Keyring;
use Keyring\Models\Authenticator;
use Keyring\Risk\Action;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Finding;
use Keyring\Risk\Signals\RepeatedFactorFailures;
use Keyring\Risk\Signals\SessionFingerprintChanged;
use Keyring\Sessions\Sessions;

const CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36';

class RevokesDuringAssessment implements Signal
{
    public static bool $fired = false;

    public function assess(Assessment $assessment): ?Finding
    {
        if (static::$fired) {
            return null;
        }

        static::$fired = true;
        app(SessionRegistry::class)->revoke($assessment->session->id);

        return new Finding('revoke_once', 60, 'Testing.');
    }

    public function checkpoints(): array
    {
        return [Checkpoint::Request];
    }
}

beforeEach(function () {
    RevokesDuringAssessment::$fired = false;
    Route::middleware(['web', 'auth'])->get('/home', fn () => 'home');

    $this->user = taylor();
});

function signInWith(string $agent = FIREFOX): void
{
    test()->withHeader('User-Agent', $agent)->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
}

dataset('drivers', ['database', 'cache']);

it('does not let anonymous wrong passwords raise the owner\'s risk', function () {
    Keyring::risk([RepeatedFactorFailures::class])->respond(fn ($risk) => $risk->has('repeated_failures') ? Action::deny() : Action::allow());
    config(['keyring.limits.per_account' => 100]);

    foreach (range(1, 6) as $guess) {
        $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'nope']);
        $this->travel(15)->seconds();
    }

    $this->travel(5)->minutes();
    signInWith();

    $this->assertAuthenticatedAs($this->user);
});

it('still counts failed second factors after a correct password', function () {
    Keyring::risk([RepeatedFactorFailures::class])->respond(fn ($risk) => $risk->has('repeated_failures') ? Action::deny() : Action::allow());
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    config(['keyring.limits.per_account' => 100]);

    foreach (range(1, 5) as $guess) {
        signInWith();
        $this->post(route('keyring.login.verify', 'totp'), ['code' => '000000']);
    }

    signInWith();

    $this->assertGuest();
    expect(session('errors')->first('email'))->toBe(__('auth.failed'));
});

it('signs out a session whose registry record expired instead of registering it again', function () {
    config(['keyring.sessions.driver' => 'cache', 'keyring.sessions.absolute' => '1h']);
    signInWith();

    $this->travel(62)->minutes();

    $this->get('/home')->assertRedirect('/login');
    $this->assertGuest();
});

it('keeps a revoked session revoked after the cache is cleared', function () {
    config(['keyring.sessions.driver' => 'cache']);
    signInWith();

    app(SessionRegistry::class)->revoke(session(Sessions::KEY));
    Cache::flush();

    $this->get('/home')->assertRedirect('/login');
});

it('does not undo a revocation that lands while a request is being assessed', function (string $driver) {
    config(['keyring.sessions.driver' => $driver]);
    Keyring::risk([new RevokesDuringAssessment]);
    signInWith();

    $this->withHeader('User-Agent', CHROME)->get('/home');

    expect(app(SessionRegistry::class)->find(session(Sessions::KEY))?->revokedAt)->not->toBeNull();
    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');
})->with('drivers');

it('applies lockFor from the request checkpoint too', function () {
    Keyring::risk([SessionFingerprintChanged::class])
        ->respond(fn ($risk) => $risk->isElevated() ? Action::deny()->revokeAllSessions()->lockFor('1h') : Action::allow());

    signInWith();
    $this->withHeader('User-Agent', CHROME)->get('/home')->assertRedirect('/login');

    signInWith();
    $this->assertGuest();
});

it('asks again for laravel password confirmation after a mid-session step-up', function () {
    Keyring::risk([SessionFingerprintChanged::class]);
    Route::middleware(['web', 'auth'])->get('/password-confirm', fn () => 'confirm')->name('password.confirm');
    Route::middleware(['web', 'auth', 'password.confirm'])->get('/billing', fn () => 'billing');

    signInWith();
    $this->withHeader('User-Agent', FIREFOX)->get(route('keyring.confirm.challenge'));
    $this->withHeader('User-Agent', FIREFOX)->post(route('keyring.confirm.verify', 'password'), ['password' => 'password']);
    $this->withHeader('User-Agent', FIREFOX)->get('/billing')->assertOk();

    $this->withHeader('User-Agent', CHROME)->get('/home')->assertOk();

    $this->withHeader('User-Agent', CHROME)->get('/billing')->assertRedirect('/password-confirm');
});
