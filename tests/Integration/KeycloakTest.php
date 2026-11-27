<?php

declare(strict_types=1);

use Illuminate\Http\Client\Events\ResponseReceived;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Sleep;
use Illuminate\Support\Str;
use Keyring\Enums\Assurance;
use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\SsoFailed;
use Keyring\Facades\Keyring;
use Keyring\Factors\Password;
use Keyring\Factors\RecoveryCodes;
use Keyring\Factors\SingleSignOn;
use Keyring\Factors\Totp;
use Keyring\Models\Authenticator;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sso\SignedToken;
use Keyring\Tests\Fixtures\User;
use Keyring\Tests\Integration\Keycloak;

// Signing in with a real OpenID Connect provider: Keycloak, started by
// bin/keycloak. Everything Keyring sends it goes over HTTP, nothing is
// faked, and its browser half is driven with a cookie jar. Skipped unless
// KEYRING_KEYCLOAK_URL says where it is.
beforeEach(function () {
    $this->realm = null;
    $url = getenv('KEYRING_KEYCLOAK_URL');

    if (! is_string($url) || $url === '') {
        $this->markTestSkipped('Set KEYRING_KEYCLOAK_URL to a Keycloak started by bin/keycloak.');
    }

    $this->keycloak = new Keycloak(rtrim($url, '/'));
    Keyring::factors([Password::class, Totp::class, RecoveryCodes::class, SingleSignOn::class]);
    useRealm($this->keycloak);

    // What Keyring's own requests to Keycloak got back.
    $this->responses = collect();
    Event::listen(ResponseReceived::class, fn (ResponseReceived $event) => $this->responses->push($event));

    $this->user = taylor(['password' => null]);
});

afterEach(function () {
    $this->realm?->deleteRealm();
});

/**
 * Point the "keycloak" provider at the realm. Keyring only registers its
 * routes for single sign-on with a provider configured, so they're
 * registered again, with a page that needs a recent verification.
 *
 * @param  array<string, mixed>  $config
 */
function useRealm(Keycloak $keycloak, array $config = []): void
{
    config(['keyring.sso.providers.keycloak' => [
        'driver' => 'oidc',
        'issuer' => $keycloak->issuer(),
        'client_id' => Keycloak::CLIENT_ID,
        'client_secret' => Keycloak::CLIENT_SECRET,
        ...$config,
    ]]);

    reloadRoutes();
    Route::get('/settings/danger', fn () => 'danger zone')->middleware(['web', 'auth', 'keyring.fresh:15m']);
}

function keycloakLink(User $user, Keycloak $keycloak): Authenticator
{
    return Authenticator::factory()->sso('keycloak', $keycloak->subject(), $keycloak->issuer())->for($user, 'authenticatable')->create();
}

/**
 * Click "Sign in with Keycloak": where Keyring sends the browser.
 */
function keycloakButton(): string
{
    return test()->get(route('keyring.sso.redirect', 'keycloak'))->assertRedirect()->headers->get('Location');
}

/**
 * @return array<string, string>
 */
function queryOf(string $url): array
{
    parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

    return $query;
}

/**
 * The ID token Keycloak's token endpoint last sent Keyring.
 */
function lastIdToken(): SignedToken
{
    $exchange = test()->responses->last(fn (ResponseReceived $event) => str_ends_with($event->request->url(), '/protocol/openid-connect/token'));

    return SignedToken::parse($exchange->response->json('id_token'));
}

/**
 * How many times Keyring read the realm's signing keys.
 */
function keysRead(): int
{
    return test()->responses->filter(fn (ResponseReceived $event) => str_ends_with($event->request->url(), '/protocol/openid-connect/certs'))->count();
}

/**
 * A realm of its own, whose client and keys a test can change, with the
 * user's account there linked.
 *
 * @param  array<string, mixed>  $client  see Keycloak::createRealm()
 * @param  array<string, mixed>  $config  for the provider
 */
function ownRealm(array $client = [], array $config = []): Keycloak
{
    $realm = test()->keycloak->createRealm('keyring-'.Str::lower(Str::random(8)), $client);
    test()->realm = $realm;
    useRealm($realm, $config);
    keycloakLink(test()->user, $realm);

    return $realm;
}

it('reads what Keyring relies on from discovery', function () {
    expect($this->keycloak->discovery())->toMatchArray([
        'issuer' => $this->keycloak->issuer(),
        'claims_parameter_supported' => true,
        'authorization_response_iss_parameter_supported' => true,
    ])
        ->and($this->keycloak->discovery()['id_token_signing_alg_values_supported'])->toContain('RS256', 'ES256')
        ->and($this->keycloak->discovery()['token_endpoint_auth_methods_supported'])->toContain('client_secret_basic')
        ->and($this->keycloak->discovery()['code_challenge_methods_supported'])->toContain('S256');
});

it('signs in the user who linked the account', function () {
    $link = keycloakLink($this->user, $this->keycloak);

    $url = keycloakButton();
    $query = queryOf($url);

    // PKCE and auth_time asked for with the claims parameter, which
    // Keycloak takes: it shows its login form rather than an error.
    expect($url)->toStartWith($this->keycloak->issuer().'/protocol/openid-connect/auth?')
        ->and($query)->toMatchArray([
            'client_id' => Keycloak::CLIENT_ID,
            'redirect_uri' => Keycloak::CALLBACK,
            'code_challenge_method' => 'S256',
            'claims' => '{"id_token":{"auth_time":{"essential":true}}}',
        ]);

    $callback = $this->keycloak->signIn($url);

    // RFC 9207: Keycloak says who it is on the callback.
    expect(queryOf($callback)['iss'])->toBe($this->keycloak->issuer());

    $this->get($callback)->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(lastIdToken()->algorithm())->toBe('RS256')
        ->and(lastIdToken()->claims['auth_time'])->toBeInt()
        ->and($link->fresh()->meta('email'))->toBe('taylor@example.com')
        ->and(logEntry('signed_in')->meta['factors'])->toBe(['sso']);

    // Asked for in the sign in, the auth_time Keycloak sent is when the
    // user proved who they are, so it counts as recent.
    $verification = app(SessionAssurance::class)->all()[0];
    expect($verification->authenticatedAt)->toBe(lastIdToken()->claims['auth_time']);
    $this->get('/settings/danger')->assertOk()->assertSee('danger zone');
});

it('links an account at Keycloak', function () {
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1);

    $url = $this->postJson(route('keyring.authenticators.store', 'sso'), ['provider' => 'keycloak'])->assertOk()->json('enrollment.url');

    $this->get($this->keycloak->signIn($url))->assertSessionHas('status', 'authenticator-added');

    $link = $this->user->keyring->refresh()->of('sso')->sole();
    expect($link->credential_id)->toBe(SingleSignOn::credentialId($this->keycloak->issuer(), $this->keycloak->subject()))
        ->and($link->meta)->toEqual([
            'provider' => 'keycloak',
            'issuer' => $this->keycloak->issuer(),
            'subject' => $this->keycloak->subject(),
            'email' => 'taylor@example.com',
        ])
        ->and($link->name)->toBe('Keycloak (taylor@example.com)');

    // Signed out here, the link signs them back in.
    Auth::logout();
    session()->flush();

    $this->get($this->keycloak->passThrough(keycloakButton()))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('confirms a step-up by having the user sign in at Keycloak again', function () {
    keycloakLink($this->user, $this->keycloak);

    // Signed in at Keycloak already, so only prompt=login has it ask again.
    $this->keycloak->signIn(Keyring::sso()->start('keycloak', SingleSignOn::LOGIN, Keycloak::CALLBACK));
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

    $sentAt = now()->getTimestamp();
    $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    $challenge = $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'sso')->json('props.challenge.url');
    $url = $this->get($challenge)->assertRedirect()->headers->get('Location');

    expect(queryOf($url))->toMatchArray(['max_age' => '0', 'prompt' => 'login', 'login_hint' => 'taylor@example.com']);

    $this->get($this->keycloak->signIn($url))->assertRedirect('http://localhost/settings/danger');

    expect(lastIdToken()->claims['auth_time'])->toBeGreaterThanOrEqual($sentAt);
    $this->get('/settings/danger')->assertOk()->assertSee('danger zone');
});

it('refuses to confirm a step-up with another account at Keycloak', function () {
    $realm = ownRealm();
    $realm->addUser('someone');
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

    $challenge = $this->getJson(route('keyring.confirm.challenge'))->json('props.challenge.url');
    $challenge = $this->getJson(route('keyring.confirm.challenge'))->json('props.challenge.url');
    $url = $this->get($challenge)->assertRedirect()->headers->get('Location');

    $this->get($realm->signIn($url, username: 'someone'))->assertRedirect(route('keyring.confirm.challenge'))->assertSessionHasErrors();

    $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    $this->assertAuthenticatedAs($this->user);
});

it('signs nobody in with an account at Keycloak nobody linked', function () {
    $realm = ownRealm();
    $realm->addUser('someone');

    $this->get($realm->signIn(keycloakButton(), username: 'someone'))->assertRedirect('/login')->assertSessionHasErrors(['email' => __('auth.failed')]);

    $this->assertGuest();
});

it('counts a sign in Keycloak lets straight through as no more recent than its session there', function () {
    keycloakLink($this->user, $this->keycloak);

    $this->get($this->keycloak->signIn(keycloakButton()))->assertRedirect('/dashboard');
    $signedInAt = lastIdToken()->claims['auth_time'];

    $this->post(route('logout'));
    $this->assertGuest();

    // Long enough after that a page asking for the last few seconds
    // doesn't take it.
    Route::get('/settings/just-now', fn () => 'just now')->middleware(['web', 'auth', 'keyring.fresh:2s']);
    Sleep::sleep(3);

    // No password asked for: Keycloak's session from before is enough.
    $this->get($this->keycloak->passThrough(keycloakButton()))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(lastIdToken()->claims['auth_time'])->toBe($signedInAt);

    $verification = app(SessionAssurance::class)->all()[0];
    expect($verification->authenticatedAt)->toBe($signedInAt)
        ->and($verification->at)->toBeGreaterThan($signedInAt + 2);
    $this->get('/settings/just-now')->assertRedirect(route('keyring.confirm.challenge'));
});

it('never counts a sign in at Keycloak as fresh, nor offers it on the confirm page, with "freshness" set to never', function () {
    useRealm($this->keycloak, ['freshness' => 'never']);
    keycloakLink($this->user, $this->keycloak);

    // Asked for a password there and then, and still not fresh.
    $url = keycloakButton();
    expect(queryOf($url))->not->toHaveKey('claims');
    $this->get($this->keycloak->signIn($url))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    expect(app(SessionAssurance::class)->all()[0]->provedAt())->toBe(0);
    // With nothing else to confirm with, they're sent to enroll straight away.
    $this->getJson('/settings/danger')->assertForbidden()->assertJsonPath('status', 'enroll-first');
});

it('counts a sign in, and a confirm, Keycloak lets straight through as fresh with "freshness" set to round_trip', function () {
    useRealm($this->keycloak, ['freshness' => 'round_trip']);
    keycloakLink($this->user, $this->keycloak);

    // Signed in at Keycloak already.
    $this->keycloak->signIn(Keyring::sso()->start('keycloak', SingleSignOn::LOGIN, Keycloak::CALLBACK));
    $this->actingAs($this->user)->withAssurance(Assurance::AAL1)->freshAt(now()->subHour());

    $this->get('/settings/danger')->assertRedirect(route('keyring.confirm.challenge'));
    $challenge = $this->getJson(route('keyring.confirm.challenge'))->assertOk()->assertJsonPath('props.factor', 'sso')->json('props.challenge.url');
    $url = $this->get($challenge)->assertRedirect()->headers->get('Location');

    expect(queryOf($url))->not->toHaveKeys(['max_age', 'prompt', 'claims']);

    // No password asked for: Keycloak's session is enough.
    $this->get($this->keycloak->passThrough($url))->assertRedirect('http://localhost/settings/danger');
    $this->get('/settings/danger')->assertOk()->assertSee('danger zone');
});

it('refuses a callback that says it came from another issuer, or leaves out who it came from', function () {
    keycloakLink($this->user, $this->keycloak);
    Exceptions::fake();

    $callback = $this->keycloak->signIn(keycloakButton());
    $issuer = 'iss='.urlencode($this->keycloak->issuer());
    expect($callback)->toContain($issuer);

    $this->get(str_replace($issuer, 'iss='.urlencode('https://evil.example.com'), $callback))->assertRedirect('/login');

    // Keycloak's discovery says it always sends iss, so it can't be dropped.
    $this->get(str_replace($issuer, 'from=elsewhere', $this->keycloak->passThrough(keycloakButton())))->assertRedirect('/login');

    $this->assertGuest();
    Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::InvalidResponse && str_contains($e->getMessage(), 'came from another issuer'));
    Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::InvalidResponse && str_contains($e->getMessage(), 'has no iss'));
});

it('reports a wrong client secret as a failed exchange', function () {
    keycloakLink($this->user, $this->keycloak);
    useRealm($this->keycloak, ['client_secret' => 'not-the-secret']);
    Exceptions::fake();

    $this->get($this->keycloak->signIn(keycloakButton()))->assertRedirect('/login')->assertSessionHasErrors('email');

    $this->assertGuest();
    Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::ExchangeFailed
        && str_contains($e->getMessage(), '(401) with the error [unauthorized_client]'));
});

it('sends the secret in the form when the config says to', function () {
    keycloakLink($this->user, $this->keycloak);
    useRealm($this->keycloak, ['token_endpoint_auth_method' => 'client_secret_post']);

    $this->get($this->keycloak->signIn(keycloakButton()))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
});

it('signs in with a public client, which only has PKCE to prove it asked', function () {
    $realm = ownRealm(['publicClient' => true], ['client_secret' => null]);

    $this->get($realm->signIn(keycloakButton()))->assertRedirect('/dashboard');

    $this->assertAuthenticatedAs($this->user);
    $exchange = $this->responses->last(fn (ResponseReceived $event) => str_ends_with($event->request->url(), '/token'));
    expect($exchange->request->hasHeader('Authorization'))->toBeFalse()
        ->and($exchange->request->data())->toHaveKey('client_id', Keycloak::CLIENT_ID)->not->toHaveKey('client_secret');
});

it('takes the user declining at Keycloak as cancelled, and reports nothing', function () {
    $realm = ownRealm(['consentRequired' => true]);
    Exceptions::fake();

    $callback = $realm->signIn(keycloakButton(), consent: false);

    expect(queryOf($callback))->toMatchArray(['error' => 'access_denied', 'iss' => $realm->issuer()]);
    $this->get($callback)->assertRedirect('/login')->assertSessionHas('status', 'sso-cancelled');

    $this->assertGuest();
    Exceptions::assertNothingReported();
});

it('reports an error Keycloak sends back, such as prompt=none without a session there', function () {
    useRealm($this->keycloak, ['parameters' => ['prompt' => 'none']]);
    Exceptions::fake();

    $callback = $this->keycloak->passThrough(keycloakButton());

    expect(queryOf($callback))->toMatchArray(['error' => 'login_required', 'iss' => $this->keycloak->issuer()]);
    $this->get($callback)->assertRedirect('/login')->assertSessionHasErrors('email');

    Exceptions::assertReported(fn (SsoFailed $e) => $e->reason === SsoFailure::ProviderError
        && str_contains($e->getMessage(), '[login_required]'));
});

describe('signing keys', function () {
    it('takes an ID token signed with ES256', function () {
        $realm = ownRealm(['attributes' => ['id.token.signed.response.alg' => 'ES256']]);
        $realm->addKey('ecdsa-generated', ['ecdsaEllipticCurveKey' => 'P-256']);

        $this->get($realm->signIn(keycloakButton()))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        expect(lastIdToken()->algorithm())->toBe('ES256');
    });

    it('takes an ID token signed with PS256', function () {
        $realm = ownRealm(['attributes' => ['id.token.signed.response.alg' => 'PS256']]);
        $realm->addKey('rsa-generated', ['algorithm' => 'PS256']);

        $this->get($realm->signIn(keycloakButton()))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        expect(lastIdToken()->algorithm())->toBe('PS256');
    });

    it('takes an ID token signed with EdDSA', function () {
        $realm = ownRealm(['attributes' => ['id.token.signed.response.alg' => 'EdDSA']]);
        $realm->addKey('eddsa-generated', ['eddsaEllipticCurveKey' => 'Ed25519']);

        $this->get($realm->signIn(keycloakButton()))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        expect(lastIdToken()->algorithm())->toBe('EdDSA');
    });

    it('reads the keys again when Keycloak starts signing with a new one', function () {
        $realm = ownRealm();

        $this->get($realm->signIn(keycloakButton()))->assertRedirect('/dashboard');
        $oldKey = lastIdToken()->keyId();
        expect(keysRead())->toBe(1);

        $this->post(route('logout'));

        // A new key, and the old one taken out of the JWKS.
        $old = collect($realm->keyProviders())->firstWhere('providerId', 'rsa-generated');
        $realm->addKey('rsa-generated');
        $realm->disableKey($old);

        $this->get($realm->passThrough(keycloakButton()))->assertRedirect('/dashboard');

        $this->assertAuthenticatedAs($this->user);
        expect(lastIdToken()->keyId())->not->toBe($oldKey)
            ->and(keysRead())->toBe(2);
    });
});
