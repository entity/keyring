<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Factors\Factor;
use Keyring\Factors\Password;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Login\Attempt;
use Keyring\Login\AttemptStore;
use Keyring\Login\Verification;
use Keyring\Models\Authenticator;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\Signals\ImpossibleTravel;
use Keyring\Support\EncryptedSession;
use Keyring\Testing\VirtualAuthenticator;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * A factor that takes the code "ok", under whatever key it's given.
 */
function factorKeyed(string $key): Factor
{
    return new class($key) extends Factor
    {
        public function __construct(private readonly string $key) {}

        public function key(): string
        {
            return $this->key;
        }

        public function categories(Authenticator $authenticator): array
        {
            return [Category::Possession];
        }

        public function verify(Attempt $attempt, Authenticator $authenticator, Request $request): ?Verification
        {
            return $request->input('code') === 'ok' ? $this->verified($authenticator) : null;
        }
    };
}

it('compares the signed-in user\'s id with a confirmation\'s as strings', function (Closure $stored, bool $stands) {
    $user = taylor();
    $this->actingAs($user);

    $store = app(AttemptStore::class);
    $store->start(Purpose::Confirm, $user);

    // The same attempt, with the user's ID as another request might have kept it.
    $session = app(EncryptedSession::class);
    $session->put(AttemptStore::key(Purpose::Confirm), [...$session->get(AttemptStore::key(Purpose::Confirm)), 'user_id' => $stored($user->id)]);

    expect($store->current(Purpose::Confirm) !== null)->toBe($stands);
})->with([
    'the id as an integer' => [fn (int $id) => $id, true],
    'the id as a string' => [fn (int $id) => (string) $id, true],
    'a string php would take for the same number' => [fn (int $id) => '0'.$id, false],
    'a number php would take for the same number' => [fn (int $id) => $id.'e0', false],
]);

it('answers a second factor with the key that signed, not one whose id only looks equal to php', function () {
    Keyring::factors([Password::class, WebAuthn::securityKeys()]);
    $user = taylor();

    // "10e2" == "1000" in PHP, since both read as the number 1000.
    $keyWithId = fn (string $id) => (fn () => clone ($this, ['credentialId' => Base64UrlSafe::decodeNoPadding($id)]))->call(new VirtualAuthenticator(userVerification: false));
    $shown = $keyWithId('10e2');
    $other = $keyWithId('1000');

    foreach ([$shown, $other] as $key) {
        // Adding a key takes proving the ones the account already has.
        $keys = Keyring::for($user)->all()->reject->isVirtual()->all();

        $this->actingAs($user);
        $keys === [] ? $this->withAssurance(Assurance::AAL2) : $this->verifiedWith(...$keys);
        $options = $this->postJson(route('keyring.authenticators.store', 'security-key'))->json('enrollment.options');
        $this->postJson(route('keyring.authenticators.confirm', 'security-key'), ['credential' => $key->register($options)])->assertOk();
        $this->post('/logout');
    }

    expect(Authenticator::oldest('id')->pluck('credential_id')->all())->toBe(['10e2', '1000']);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));
    $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
    $this->flushHeaders();

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $other->assert($options)])->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($user);
});

it('does not take a value that is not an authenticator\'s id for the first one', function (mixed $id) {
    Keyring::factors([Password::class, Totp::class]);
    $user = taylor();

    $first = Authenticator::factory()->totp()->for($user, 'authenticatable')->create();
    Authenticator::factory()->totp()->for($user, 'authenticatable')->create();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

    // With two to choose from and no ID that names one, none is checked,
    // even with a code the first would take.
    $this->postJson(route('keyring.login.verify', 'totp'), ['authenticator' => $id, 'code' => $this->totpCode($first)])->assertUnprocessable();

    $this->assertGuest();
})->with([
    'true' => [true],
    'zero' => [0],
]);

it('keeps factors whose keys only look equal to php apart', function () {
    // "10" == "1e1" in PHP.
    Keyring::factors([Password::class, factorKeyed('10'), factorKeyed('1e1')]);
    $user = taylor();

    $ten = Authenticator::factory()->for($user, 'authenticatable')->create(['factor' => '10', 'secret' => null]);
    $other = Authenticator::factory()->for($user, 'authenticatable')->create(['factor' => '1e1', 'secret' => null]);

    expect($user->keyring->of('10')->pluck('id')->all())->toBe([$ten->id])
        ->and($user->keyring->of('1e1')->pluck('id')->all())->toBe([$other->id])
        ->and($user->keyring->all()->where('id', $ten->id))->toHaveCount(1);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect(route('keyring.login.challenge'));

    // One authenticator has this factor, so there's no doubt which is meant.
    $this->post(route('keyring.login.verify', '10'), ['code' => 'ok'])->assertRedirect('/dashboard');
});

it('takes rate limits that the environment gave as strings', function () {
    config(['keyring.limits' => [...config('keyring.limits'), 'per_account' => '5', 'per_ip' => '20', 'consecutive' => '100', 'lock_after' => '3', 'codes' => '3', 'notices' => '5']]);

    taylor();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])->assertRedirect('/dashboard');
});

it('measures travel from coordinates a locator gave as text, and has none to measure from words', function (array $there, array $here, bool $found) {
    $user = taylor();

    Keyring::deviceModel()::query()->create([
        'authenticatable_type' => $user->getMorphClass(),
        'authenticatable_id' => $user->id,
        'token_hash' => str_repeat('a', 64),
        'location' => $there,
        'last_seen_at' => now()->subMinutes(10),
    ]);

    $this->app->instance(LocatesIps::class, new readonly class($here) implements LocatesIps
    {
        public function __construct(private array $location) {}

        public function locate(Request $request): array
        {
            return $this->location;
        }
    });

    $finding = new ImpossibleTravel()->assess(new Assessment(Checkpoint::Login, Request::create('/login', 'POST'), $user));

    expect($finding !== null)->toBe($found);
})->with([
    'text' => [['latitude' => '51.5', 'longitude' => '-0.12'], ['latitude' => '-33.87', 'longitude' => '151.21'], true],
    'whole numbers' => [['latitude' => 51, 'longitude' => 0], ['latitude' => -34, 'longitude' => 151], true],
    'words' => [['latitude' => 'north', 'longitude' => 'west'], ['latitude' => '-33.87', 'longitude' => '151.21'], false],
]);

it('shows no status message for a status the app flashed that is not text', function (mixed $status, ?string $shown) {
    $this->withSession(['status' => $status])->inertia()->get(route('password.request'))
        ->assertOk()
        ->assertJsonPath('props.status', $shown);
})->with([
    'a number' => [1, null],
    'a boolean' => [true, null],
    'a list' => [['saved'], null],
    'the broker\'s own message' => ['We have emailed your password reset link.', 'We have emailed your password reset link.'],
]);
