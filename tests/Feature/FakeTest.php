<?php

declare(strict_types=1);

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Pipeline\Steps\VerifyFactor;
use Keyring\Sessions\SessionAssurance;
use Keyring\Testing\FakeVerifyFactor;
use Keyring\Testing\KeyringFake;
use PHPUnit\Framework\ExpectationFailedException;

beforeEach(function () {
    Keyring::factors([Password::class, Totp::class, WebAuthn::securityKeys(), RecoveryCodes::class]);
    $this->user = taylor();
});

afterEach(function () {
    // Testbench rolls back migrations after a test, which asks to confirm in production.
    app()->detectEnvironment(fn () => 'testing');
});

function runningIn(string $environment): void
{
    app()->detectEnvironment(fn () => $environment);

    // Laravel only skips this check in the testing environment.
    test()->withoutMiddleware(PreventRequestForgery::class);
}

it('refuses to fake in production', function () {
    runningIn('production');

    expect(fn () => Keyring::fake())->toThrow(LogicException::class, 'cannot be used in production');
    expect(app()->bound(KeyringFake::class))->toBeFalse();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->assertGuest();
});

it('does not pass a factor for a fake bound by hand in production', function () {
    runningIn('production');
    app()->instance(KeyringFake::class, (new KeyringFake)->pass('password'));
    app()->bind(VerifyFactor::class, FakeVerifyFactor::class);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->post('/login', ['email' => 'taylor@example.com'])->assertSessionHasErrors('password');
    $this->assertGuest();
});

it('does not fail a factor for a fake bound by hand in production', function () {
    runningIn('production');
    app()->instance(KeyringFake::class, (new KeyringFake)->fail('password'));
    app()->bind(VerifyFactor::class, FakeVerifyFactor::class);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('checks for real when a fake is in the container but nothing asked to fake', function () {
    app()->instance(KeyringFake::class, (new KeyringFake)->pass('password'));

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->assertGuest();
});

it('still fakes outside production, so browser suites keep working', function (string $environment) {
    runningIn($environment);
    Keyring::fake()->pass('password');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
})->with(['local', 'staging']);

it('passes factors without real proofs', function () {
    Keyring::require(Requirement::aal2()->phishingResistant());
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    Keyring::fake()->pass('security-key');

    $this->get(route('keyring.login.challenge'));
    $this->post(route('keyring.login.verify', 'security-key'))->assertRedirect('/dashboard');

    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
});

it('fails factors on demand', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    Keyring::fake()->fail('totp');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '123456'])->assertSessionHasErrors('code');

    $this->assertGuest();
});

it('still identifies users for real', function () {
    Keyring::fake()->pass('password');

    $this->post('/login', ['email' => 'nobody@example.com', 'password' => 'anything'])->assertSessionHasErrors('email');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'anything'])->assertRedirect('/dashboard');
});

it('enforces no downgrade for users with phishing resistant factors', function () {
    Keyring::require(Requirement::aal2()->noDowngrade());
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->default()->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $response = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'security-key');
    expect($response->json('props.alternatives'))->toBe([]);

    Keyring::fake()->pass('totp');
    $this->post(route('keyring.login.verify', 'totp'))->assertSessionHasErrors();
    $this->assertGuest();
});

it('still offers recovery codes under no downgrade, so a lost key is not a lockout', function () {
    Keyring::require(Requirement::aal2()->noDowngrade());
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    $response = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'security-key');
    expect(collect($response->json('props.alternatives'))->pluck('factor')->all())->toBe(['recovery']);
    $this->flushHeaders();

    $this->post(route('keyring.login.verify', 'recovery'), ['code' => 'aaaa-aaaa-aaaa-aaaa-aaaa-aaaa-aa'])->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('can refuse recovery codes under no downgrade as well', function () {
    Keyring::require(Requirement::aal2()->noDowngrade(except: []));
    Authenticator::factory()->securityKey()->for($this->user, 'authenticatable')->create();
    Authenticator::factory()->recoveryCodes()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);

    expect($this->inertia()->get(route('keyring.login.challenge'))->json('props.alternatives'))->toBe([]);
});

it('asserts which factors were checked and how they went', function () {
    Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();
    $fake = Keyring::fake()->fail('totp');

    $fake->assertNothingChecked();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong']);
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => '123456']);

    $fake->assertFailed('password', 1)
        ->assertVerified('password')
        ->assertFailed('totp')
        ->assertNotChecked('recovery');

    expect(fn () => $fake->assertVerified('totp'))->toThrow(ExpectationFailedException::class, 'The [totp] factor never verified.')
        ->and(fn () => $fake->assertNotChecked('totp'))->toThrow(ExpectationFailedException::class);
});

it('acts as a session verified with real authenticators', function () {
    $this->freezeSecond();

    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->actingAs($this->user)->verifiedWith($totp)->freshAt(now()->subMinutes(5))->get('/');

    $verifications = app(SessionAssurance::class)->all();

    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2)
        ->and(collect($verifications)->pluck('authenticator')->all())->toBe([null, $totp->id])
        ->and(collect($verifications)->pluck('at')->unique()->all())->toBe([now()->subMinutes(5)->getTimestamp()]);
});

it('gives the code an authenticator app would show', function () {
    $totp = Authenticator::factory()->totp()->for($this->user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $this->post(route('keyring.login.verify', 'totp'), ['code' => $this->totpCode($totp)])->assertRedirect('/dashboard');

    expect($this->totpCode($totp->secret))->toBe($this->totpCode($totp));
});
