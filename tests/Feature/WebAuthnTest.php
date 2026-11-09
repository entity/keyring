<?php

use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Routing\RouteCollection;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Keyring\Enums\Assurance;
use Keyring\Enums\Category;
use Keyring\Enums\Purpose;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\Totp;
use Keyring\Factors\WebAuthn;
use Keyring\Features;
use Keyring\Login\Attempt;
use Keyring\Login\Requirement;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Testing\VirtualAuthenticator;
use Keyring\Tests\Fixtures\AdminUser;
use Keyring\Tests\Fixtures\Staff;
use Keyring\WebAuthn\Ceremonies;
use Webauthn\CredentialRecord;

beforeEach(function () {
    Keyring::factors([
        Password::class,
        Totp::class,
        WebAuthn::passkeys(),
        WebAuthn::securityKeys(),
        RecoveryCodes::class,
    ]);

    $this->user = taylor();
});

function enroll(string $factor, VirtualAuthenticator $key, string $name = 'My key'): void
{
    test()->actingAs(test()->user)->withAssurance(Assurance::AAL2);

    $options = test()->postJson(route('keyring.authenticators.store', $factor))->assertOk()->json('enrollment.options');

    test()->postJson(route('keyring.authenticators.confirm', $factor), [
        'credential' => $key->register($options),
        'name' => $name,
    ])->assertOk();

    test()->post('/logout');
}

it('registers a passkey', function () {
    $key = new VirtualAuthenticator;

    enroll('passkey', $key, 'MacBook');

    $passkey = $this->user->keyring->of('passkey')->first();

    expect($passkey->name)->toBe('MacBook')
        ->and($passkey->meta('user_verified'))->toBeTrue()
        ->and($passkey->factor()->categories($passkey))->toBe([Category::Possession, Category::Inherence]);
});

it('signs in with a passkey alone, without a username', function (VirtualAuthenticator $key) {
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))
        ->assertOk()
        ->assertJsonPath('allowCredentials', [])
        ->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
})->with([
    'P-256' => fn () => new VirtualAuthenticator,
    'Ed25519' => fn () => VirtualAuthenticator::eddsa(),
]);

it('caps a passkey that syncs at aal2, as nist does', function () {
    $key = new VirtualAuthenticator(synced: true);
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');

    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL2)
        ->and($this->user->keyring->canMeet(Requirement::aal3()))->toBeFalse();
});

it('will not sign in with a passkey that belongs to another model with the same id', function () {
    $user = $this->user;
    $key = new VirtualAuthenticator;
    // Staff accounts are made by admins, not registered, so needn't verify an email.
    config(['keyring.features' => array_values(array_diff(Features::all(), [Features::registration()]))]);
    $this->user = staff();
    enroll('passkey', $key);

    expect($this->user->getKey())->toBe($user->getKey())
        ->and(Authenticator::where('factor', 'passkey')->sole()->authenticatable_type)->toBe(Staff::class);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertSessionHasErrors(['credential' => __('auth.failed')]);

    $this->assertGuest();
    Auth::forgetGuards();
    $this->get(route('keyring.confirm.challenge'))->assertRedirect(route('login'));
    expect(Authenticator::where('factor', 'passkey')->sole()->last_used_at)->toBeNull();

});

it('leaves the owner check to a guard provider that is not eloquent', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $found = null;
    config(['auth.providers.users.driver' => 'custom']);
    Auth::provider('custom', function () use (&$found) {
        return Mockery::mock(UserProvider::class, ['retrieveById' => $found]);
    });

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertSessionHasErrors(['credential' => __('auth.failed')]);
    $this->assertGuest();

    $found = $this->user;

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');
    $this->assertAuthenticatedAs($this->user);
});

it('signs in a subclass of the guard\'s model with its passkey', function () {
    $key = new VirtualAuthenticator;
    $this->user = AdminUser::query()->findOrFail($this->user->getKey());
    enroll('passkey', $key);

    expect(Authenticator::where('factor', 'passkey')->sole()->authenticatable_type)->toBe(AdminUser::class);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticated();
});

it('still signs a user in with their own passkey when another model has the same id', function () {
    $key = new VirtualAuthenticator;
    $staff = staff();
    enroll('passkey', $key);

    expect($staff->getKey())->toBe($this->user->getKey());

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('signs in the other model with its passkey when that model is behind keyring\'s guard', function () {
    config([
        'auth.providers.staff' => ['driver' => 'eloquent', 'model' => Staff::class],
        'auth.guards.staff' => ['driver' => 'session', 'provider' => 'staff'],
        'auth.defaults.guard' => 'staff',
        'keyring.guard' => 'staff',
    ]);
    Route::setRoutes(new RouteCollection);
    Keyring::routes();

    $key = new VirtualAuthenticator;
    // Staff accounts are made by admins, not registered, so needn't verify an email.
    config(['keyring.features' => array_values(array_diff(Features::all(), [Features::registration()]))]);
    $this->user = staff();
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user, 'staff');
});

it('keeps credential ids unique across models', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    // Staff accounts are made by admins, not registered, so needn't verify an email.
    config(['keyring.features' => array_values(array_diff(Features::all(), [Features::registration()]))]);
    $this->user = staff();
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->assertOk()->json('enrollment.options');

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])
        ->assertUnprocessable();

    expect(Authenticator::where('factor', 'passkey')->count())->toBe(1);
});

it('uses a security key as a second factor', function () {
    $key = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $key);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $options = $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.factor', 'security-key')
        ->json('props.challenge.options');

    expect($options['allowCredentials'])->toHaveCount(1);

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(app(SessionAssurance::class)->level())->toBe(Assurance::AAL3);
});

it('does not let a security key sign in without a password', function () {
    $key = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $key);

    $this->getJson(route('keyring.login.options', 'security-key'))->assertNotFound();

    $this->post(route('keyring.login.factor', 'security-key'), ['credential' => $key->assert(['challenge' => 'x', 'rpId' => 'localhost'])])
        ->assertNotFound();

    $this->assertGuest();
});

it('only counts inherence when the key verified the user', function () {
    Keyring::require(Requirement::factors(3));
    $key = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $key);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)]);

    $this->assertGuest();
});

it('accepts any of the user\'s keys, not just the one shown', function () {
    $first = new VirtualAuthenticator(userVerification: false);
    $second = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $first, 'First');
    enroll('security-key', $second, 'Second');

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $options = $this->inertia()->get(route('keyring.login.challenge'))
        ->assertJsonPath('props.authenticator.name', 'First')
        ->json('props.challenge.options');

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $second->assert($options)])
        ->assertRedirect('/dashboard');

    expect($this->user->keyring->refresh()->of('security-key')->firstWhere('name', 'Second')->last_used_at)->not->toBeNull();
});

it('rejects responses from another origin', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options, origin: 'https://evil.example')])
        ->assertSessionHasErrors('credential');

    $this->assertGuest();
});

it('rejects a replayed challenge', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $credential = $key->assert($options);

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $credential])->assertRedirect('/dashboard');
    $this->post('/logout');

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $credential])->assertSessionHasErrors('credential');
    $this->assertGuest();
});

it('rejects a cloned key whose counter went backwards', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)]);
    $this->post('/logout');

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->rewindCounter()->assert($options)])
        ->assertSessionHasErrors('credential');
});

it('will not register the same key twice', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);
    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');

    expect($options['excludeCredentials'])->toHaveCount(1);

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])
        ->assertUnprocessable();
});

it('lets a passkey satisfy a phishing resistant policy', function () {
    Keyring::require(Requirement::aal2()->phishingResistant());
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);
    $this->travel(1)->minutes();

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $response = $this->inertia()->get(route('keyring.login.challenge'))->assertJsonPath('props.factor', 'passkey');

    expect(collect($response->json('props.alternatives'))->pluck('factor'))->not->toContain('totp', 'recovery');

    $this->post(route('keyring.login.verify', 'passkey'), ['credential' => $key->assert($response->json('props.challenge.options'))])
        ->assertRedirect('/dashboard');
});

it('answers from the app\'s own origin by default, port and all', function () {
    config(['app.url' => 'http://localhost:8765']);
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])->assertRedirect('/dashboard');
});

it('does not let a usernameless challenge finish the second factor of a password login', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    // Autofill on the login page minted this, then the user typed a password.
    $usernameless = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password'])
        ->assertRedirect(route('keyring.login.challenge'));

    $this->post(route('keyring.login.verify', 'passkey'), ['credential' => $key->assert($usernameless)])
        ->assertSessionHasErrors('credential');
    $this->assertGuest();

    // The challenge page's own still works.
    $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
    $this->post(route('keyring.login.verify', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');
});

it('does not let a usernameless challenge confirm a step-up', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $usernameless = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->actingAs($this->user);
    $this->inertia()->get(route('keyring.confirm.challenge', 'password'))->assertJsonPath('props.factor', 'password');

    $this->post(route('keyring.confirm.verify', 'passkey'), ['credential' => $key->assert($usernameless)])
        ->assertSessionHasErrors('credential');

    $options = $this->inertia()->get(route('keyring.confirm.challenge', 'passkey'))->json('props.challenge.options');
    $this->post(route('keyring.confirm.verify', 'passkey'), ['credential' => $key->assert($options)])
        ->assertSessionHasNoErrors();
});

it('spends a usernameless challenge even when the key that answered is unknown', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();

    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => new VirtualAuthenticator()->assert($options)])
        ->assertSessionHasErrors('credential');
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertSessionHasErrors('credential');
    $this->assertGuest();

    $options = $this->getJson(route('keyring.login.options', 'passkey'))->json();
    $this->post(route('keyring.login.factor', 'passkey'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');
});

it('spends a second factor challenge even when the key that answered is unknown', function () {
    $key = new VirtualAuthenticator(userVerification: false);
    enroll('security-key', $key);

    $this->post('/login', ['email' => 'taylor@example.com', 'password' => 'password']);
    $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');

    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => new VirtualAuthenticator(userVerification: false)->assert($options)])
        ->assertSessionHasErrors('credential');
    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])
        ->assertSessionHasErrors('credential');
    $this->assertGuest();

    $options = $this->inertia()->get(route('keyring.login.challenge'))->json('props.challenge.options');
    $this->post(route('keyring.login.verify', 'security-key'), ['credential' => $key->assert($options)])
        ->assertRedirect('/dashboard');
});

it('spends a registration challenge when the confirm fails', function () {
    $key = new VirtualAuthenticator;
    $this->actingAs($this->user)->withAssurance(Assurance::AAL2);

    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');

    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => new VirtualAuthenticator(origin: 'https://evil.example')->register($options)])
        ->assertUnprocessable();
    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])
        ->assertUnprocessable();

    expect(Authenticator::where('factor', 'passkey')->exists())->toBeFalse();

    $options = $this->postJson(route('keyring.authenticators.store', 'passkey'))->json('enrollment.options');
    $this->postJson(route('keyring.authenticators.confirm', 'passkey'), ['credential' => $key->register($options)])
        ->assertOk();
});

it('checks an assertion against the stored count, not a copy read before another finished', function () {
    $key = new VirtualAuthenticator;
    enroll('passkey', $key);

    $ceremonies = app(Ceremonies::class);
    $options = $ceremonies->requestOptions([], 'required');

    // Both requests read the row before either wrote to it.
    $first = Authenticator::where('factor', 'passkey')->sole();
    $second = Authenticator::where('factor', 'passkey')->sole();

    $older = $key->assert($ceremonies->toBrowser($options));
    $newer = $key->assert($ceremonies->toBrowser($options));

    $verify = function (Authenticator $authenticator, array $credential) use ($ceremonies, $options) {
        $attempt = Attempt::start(Purpose::Login, $this->user);
        $attempt->put('passkey', 'options', $ceremonies->toJson($options));

        return Keyring::factor('passkey')->verify($attempt, $authenticator, Request::create('/', 'POST', ['credential' => $credential]));
    };

    expect($verify($first, $newer))->not->toBeNull()
        ->and($verify($second, $older))->toBeNull();

    $stored = Authenticator::where('factor', 'passkey')->sole();

    expect($stored->sign_count)->toBe($first->sign_count)
        ->and($ceremonies->fromJson($stored->public_key, CredentialRecord::class)->counter)->toBe($first->sign_count);
});
