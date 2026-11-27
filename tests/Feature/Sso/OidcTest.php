<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Keyring\Enums\SsoFailure;
use Keyring\Sso\Metadata;
use Keyring\Testing\FakeIdentityProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;

// Nothing here may reach a real provider.
beforeEach(fn () => Http::preventStrayRequests());

it('signs in with an OpenID Connect provider, whatever its keys sign with', function (string $algorithm) {
    $idp = new FakeIdentityProvider(algorithm: $algorithm)->register();

    $identity = ssoComplete($idp->signIn(['amr' => ['pwd', 'mfa', 7], 'acr' => 'urn:mace:incommon:iap:silver', 'auth_time' => 1_700_000_000])->approve(ssoStart()));

    expect($identity->provider)->toBe('fake')
        ->and($identity->issuer)->toBe('https://idp.test')
        ->and($identity->subject)->toBe('248289761001')
        ->and($identity->email)->toBe('taylor@example.com')
        ->and($identity->emailVerified)->toBeTrue()
        ->and($identity->name)->toBe('Taylor Otwell')
        ->and($identity->amr)->toBe(['pwd', 'mfa'])
        ->and($identity->acr)->toBe('urn:mace:incommon:iap:silver')
        ->and($identity->authTime)->toBe(1_700_000_000)
        ->and($identity->claims['aud'])->toBe(FakeIdentityProvider::CLIENT_ID)
        ->and($identity->request->purpose)->toBe('login');
})->with(['ES256', 'RS256', 'PS256', 'EdDSA']);

it('sends the user with a PKCE challenge, a state and a nonce, and the code back with its verifier', function () {
    $idp = new FakeIdentityProvider()->register(config: ['parameters' => ['prompt' => 'select_account'], 'scopes' => ['email']]);

    $url = ssoStart();
    $query = authorizationQuery($url);

    expect($url)->toStartWith('https://idp.test/authorize?')
        ->and($query)->toMatchArray([
            'response_type' => 'code',
            'client_id' => FakeIdentityProvider::CLIENT_ID,
            'redirect_uri' => SSO_CALLBACK,
            'scope' => 'openid email',
            'code_challenge_method' => 'S256',
            'prompt' => 'select_account',
        ])
        ->and($query)->not->toHaveKey('response_mode')
        ->and($query['state'])->toHaveLength(43)
        ->and($query['nonce'])->toHaveLength(43)
        ->and($query['nonce'])->not->toBe($query['state'])
        ->and(ssoStart())->not->toBe($url);

    ssoComplete($idp->approve($url));

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://idp.test/token'
        && Base64UrlSafe::encodeUnpadded(hash('sha256', $request['code_verifier'], true)) === $query['code_challenge']
        && $request['redirect_uri'] === SSO_CALLBACK
        && $request->header('Authorization') === ['Basic '.base64_encode(FakeIdentityProvider::CLIENT_ID.':'.FakeIdentityProvider::CLIENT_SECRET)]
        && ! isset($request['client_secret']));
});

it('sends the client secret in the form when discovery lists only that', function () {
    $idp = new FakeIdentityProvider()->authMethods(['client_secret_post'])->register();

    ssoComplete($idp->approve(ssoStart()));

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://idp.test/token'
        && $request['client_secret'] === FakeIdentityProvider::CLIENT_SECRET
        && ! $request->hasHeader('Authorization'));
});

it('sends the client secret the way the config says', function () {
    $idp = new FakeIdentityProvider()->authMethods(['client_secret_basic', 'client_secret_post'])
        ->register(config: ['token_endpoint_auth_method' => 'client_secret_post']);

    ssoComplete($idp->approve(ssoStart()));

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://idp.test/token' && $request['client_secret'] === FakeIdentityProvider::CLIENT_SECRET);
});

it('sends only its ID as a public client', function () {
    $idp = new FakeIdentityProvider()->register(config: ['client_secret' => null]);

    ssoComplete($idp->approve(ssoStart()));

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://idp.test/token'
        && $request['client_id'] === FakeIdentityProvider::CLIENT_ID
        && ! isset($request['client_secret'])
        && ! $request->hasHeader('Authorization'));
});

it('only takes an address as verified when the provider says so with a boolean', function (array $claims) {
    $idp = new FakeIdentityProvider()->register();

    $identity = ssoComplete($idp->signIn($claims)->approve(ssoStart()));

    expect($identity->emailVerified)->toBeFalse();
})->with([
    'unverified' => [['email_verified' => false]],
    'a string' => [['email_verified' => 'true']],
    'left out' => [['email_verified' => null]],
    'no address' => [['email' => null]],
]);

it('reads the discovery document and keys once and keeps them', function () {
    $idp = new FakeIdentityProvider()->register();

    ssoComplete($idp->approve(ssoStart()));
    ssoComplete($idp->approve(ssoStart()));

    expect($idp->discoveryFetches)->toBe(1)->and($idp->keyFetches)->toBe(1);

    $this->travel(61)->minutes();
    ssoComplete($idp->approve(ssoStart()));

    expect($idp->discoveryFetches)->toBe(2)->and($idp->keyFetches)->toBe(2);
});

it('refuses ID tokens that fail a check', function (Closure $tamper, string $why) {
    $idp = new FakeIdentityProvider()->register();
    $url = ssoStart();
    $tamper($idp);

    [$reason, $message] = ssoFailure(fn () => ssoComplete($idp->approve($url)));

    expect($reason)->toBe(SsoFailure::InvalidToken)->and($message)->toContain($why);
})->with([
    'another issuer' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['iss' => 'https://evil.test']), 'another issuer'],
    'no issuer' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['iss' => null]), 'another issuer'],
    'another audience' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['aud' => 'someone-else']), 'another app'],
    'no audience' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['aud' => null]), 'another app'],
    'audiences without azp' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['aud' => [FakeIdentityProvider::CLIENT_ID, 'other']]), 'issued to another app'],
    'another azp' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['azp' => 'other']), 'issued to another app'],
    'expired' => [fn (FakeIdentityProvider $idp) => $idp->expired(), 'expired'],
    'no expiry' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['exp' => null]), 'expired'],
    'an expiry that is no number' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['exp' => '9999999999']), 'expired'],
    'an expiry too large' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['exp' => 1e300]), 'expired'],
    'expired past the leeway' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['exp' => now()->getTimestamp() - 60]), 'expired'],
    'issued in the future' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['iat' => now()->getTimestamp() + 120]), 'in the future'],
    'no time of issue' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['iat' => null]), 'no time of issue'],
    'not valid yet' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['nbf' => now()->getTimestamp() + 120]), 'not valid yet'],
    'a nbf that is no number' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['nbf' => 'soon']), 'not valid yet'],
    'another nonce' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['nonce' => str_repeat('a', 43)]), 'another sign in'],
    'no nonce' => [fn (FakeIdentityProvider $idp) => $idp->withClaims(['nonce' => null]), 'another sign in'],
    'no subject' => [fn (FakeIdentityProvider $idp) => $idp->signIn(['sub' => null]), 'no subject'],
    'an empty subject' => [fn (FakeIdentityProvider $idp) => $idp->signIn(['sub' => '']), 'no subject'],
    'a numeric subject' => [fn (FakeIdentityProvider $idp) => $idp->signIn(['sub' => 42]), 'no subject'],
    'a subject too long' => [fn (FakeIdentityProvider $idp) => $idp->signIn(['sub' => str_repeat('a', 256)]), 'no subject'],
    'alg none' => [fn (FakeIdentityProvider $idp) => $idp->unsigned(), 'signed with [none]'],
    'HS256 with the public key' => [fn (FakeIdentityProvider $idp) => $idp->signedWithPublicKeyAsSecret(), 'signed with [HS256]'],
    'no alg' => [fn (FakeIdentityProvider $idp) => $idp->withHeader(['alg' => null]), 'signed with [unreadable]'],
    'an unpublished key' => [fn (FakeIdentityProvider $idp) => $idp->signedWithUnpublishedKey(), 'not signed by any'],
    'an alg its key isn\'t for' => [fn (FakeIdentityProvider $idp) => $idp->withHeader(['alg' => 'RS256']), 'not signed by any'],
    'a known kid that didn\'t sign it' => [fn (FakeIdentityProvider $idp) => $idp->rotateKeys()->withHeader(['kid' => $idp->jwks()[0]['kid']]), 'not signed by any'],
    'critical extensions' => [fn (FakeIdentityProvider $idp) => $idp->withHeader(['crit' => ['exp']]), 'critical header'],
]);

it('takes ID tokens within the leeway, with fractional times, and that name it as their party', function () {
    $idp = new FakeIdentityProvider()->register();
    $now = now()->getTimestamp();

    $idp->withClaims([
        'exp' => $now - 30,
        'iat' => $now + 30.5,
        'nbf' => $now + 30,
        'aud' => [FakeIdentityProvider::CLIENT_ID, 'other'],
        'azp' => FakeIdentityProvider::CLIENT_ID,
    ]);

    expect(ssoComplete($idp->approve(ssoStart()))->subject)->toBe('248289761001');
});

it('checks a token without a key ID against every published key', function () {
    $idp = new FakeIdentityProvider()->register();
    $idp->rotateKeys()->withHeader(['kid' => null]);

    expect(ssoComplete($idp->approve(ssoStart()))->subject)->toBe('248289761001');
});

it('reads the keys again for a key ID it has not seen, as the provider rotates', function () {
    $idp = new FakeIdentityProvider()->register();
    ssoComplete($idp->approve(ssoStart()));

    $idp->rotateKeys(retireOld: true);

    expect(ssoComplete($idp->approve(ssoStart()))->subject)->toBe('248289761001')
        ->and($idp->keyFetches)->toBe(2);

    // The new keys are kept.
    ssoComplete($idp->approve(ssoStart()));

    expect($idp->keyFetches)->toBe(2);
});

it('reads the keys again only once a minute, whatever key IDs tokens make up', function () {
    $idp = new FakeIdentityProvider()->register();
    ssoComplete($idp->approve(ssoStart()));

    $idp->signedWithUnpublishedKey();
    ssoFailure(fn () => ssoComplete($idp->approve(ssoStart())));
    ssoFailure(fn () => ssoComplete($idp->approve(ssoStart())));

    expect($idp->keyFetches)->toBe(2);

    // A second rotation within the minute waits for it.
    $idp = new FakeIdentityProvider('https://rotating.test')->register('rotating');
    ssoComplete($idp->approve(ssoStart('rotating')), 'rotating');
    $idp->rotateKeys(retireOld: true);
    ssoComplete($idp->approve(ssoStart('rotating')), 'rotating');
    $idp->rotateKeys(retireOld: true);

    expect(ssoFailure(fn () => ssoComplete($idp->approve(ssoStart('rotating')), 'rotating'))[0])->toBe(SsoFailure::InvalidToken)
        ->and($idp->keyFetches)->toBe(2);

    $this->travel(Metadata::REFETCH_EVERY + 1)->seconds();

    expect(ssoComplete($idp->approve(ssoStart('rotating')), 'rotating')->subject)->toBe('248289761001')
        ->and($idp->keyFetches)->toBe(3);
});

it('refuses a callback the provider sent with an error', function () {
    $idp = new FakeIdentityProvider()->register();

    expect(ssoFailure(fn () => ssoComplete($idp->deny(ssoStart()))))->toBe([SsoFailure::Denied, 'Single sign-on failed (denied): The user declined to sign in with [fake].'])
        ->and(ssoFailure(fn () => ssoComplete($idp->deny(ssoStart(), 'temporarily_unavailable'))))->toBe([SsoFailure::ProviderError, 'Single sign-on failed (provider_error): [fake] answered with the error [temporarily_unavailable].'])
        ->and(ssoFailure(fn () => ssoComplete($idp->deny(ssoStart(), "<script>\nforged log line"))))->toBe([SsoFailure::ProviderError, 'Single sign-on failed (provider_error): [fake] answered with the error [unreadable].']);
});

it('refuses a callback without a code', function () {
    $idp = new FakeIdentityProvider()->register();
    $state = authorizationQuery(ssoStart())['state'];

    expect(ssoFailure(fn () => ssoComplete(SSO_CALLBACK.'?state='.$state))[0])->toBe(SsoFailure::InvalidResponse);
});

it('only reads the callback from the query string', function () {
    $idp = new FakeIdentityProvider()->register();
    parse_str((string) parse_url($idp->approve(ssoStart()), PHP_URL_QUERY), $callback);

    $request = Request::create(SSO_CALLBACK, 'POST', $callback);

    expect(ssoFailure(fn () => Keyring\Facades\Keyring::sso()->complete($request, 'fake'))[0])->toBe(SsoFailure::InvalidState);
});

it('holds the callback to the provider\'s issuer when it names one (RFC 9207)', function () {
    $idp = new FakeIdentityProvider()->sendsIssuer()->register();

    expect(ssoComplete($idp->approve(ssoStart()))->subject)->toBe('248289761001');

    $callback = $idp->approve(ssoStart());

    expect(ssoFailure(fn () => ssoComplete(str_replace('iss=https%3A%2F%2Fidp.test', 'iss=https%3A%2F%2Fevil.test', $callback)))[0])->toBe(SsoFailure::InvalidResponse)
        ->and(ssoFailure(fn () => ssoComplete(str_replace('&iss=https%3A%2F%2Fidp.test', '&iss[]=x', $idp->approve(ssoStart()))))[0])->toBe(SsoFailure::InvalidResponse)
        // Its discovery says it always sends one.
        ->and(ssoFailure(fn () => ssoComplete(str_replace('&iss=https%3A%2F%2Fidp.test', '', $idp->approve(ssoStart()))))[1])->toContain('has no iss');

    // A provider that doesn't say so may still send one, which then has to match.
    $other = new FakeIdentityProvider('https://other.test')->register('other');
    $callback = $other->approve(ssoStart('other')).'&iss='.urlencode('https://idp.test');

    expect(ssoFailure(fn () => ssoComplete($callback, 'other'))[0])->toBe(SsoFailure::InvalidResponse);
});

it('refuses codes the token endpoint won\'t swap', function () {
    $idp = new FakeIdentityProvider()->register();
    $url = ssoStart();
    $idp->failExchange(400, 'invalid_grant');

    expect(ssoFailure(fn () => ssoComplete($idp->approve($url))))->toBe([SsoFailure::ExchangeFailed, 'Single sign-on failed (exchange_failed): [fake]\'s token endpoint refused the code (400) with the error [invalid_grant].']);
});

it('refuses what a token endpoint sends that isn\'t tokens', function (mixed $answer, string $why) {
    Http::fake(['https://broken.test/token' => $answer]);
    new FakeIdentityProvider('https://broken.test')->register('broken');

    $state = authorizationQuery(ssoStart('broken'))['state'];

    [$reason, $message] = ssoFailure(fn () => ssoComplete(SSO_CALLBACK.'?code=nonsense&state='.$state, 'broken'));

    expect($reason)->toBe(SsoFailure::ExchangeFailed)->and($message)->toContain($why);
})->with([
    'HTML' => [fn () => Http::response('<html>Bad gateway</html>', 502), 'refused the code (502).'],
    'no access token' => [fn () => Http::response(['token_type' => 'Bearer']), 'no access token'],
    'no connection' => [fn () => Http::failedConnection(), 'could not be reached'],
]);

it('refuses a token response without an ID token, or with one it can\'t read', function (array $tokens, string $why) {
    Http::fake(['https://broken.test/token' => Http::response($tokens)]);
    new FakeIdentityProvider('https://broken.test')->register('broken');

    $state = authorizationQuery(ssoStart('broken'))['state'];

    [$reason, $message] = ssoFailure(fn () => ssoComplete(SSO_CALLBACK.'?code=nonsense&state='.$state, 'broken'));

    expect($reason)->toBe(SsoFailure::InvalidToken)->and($message)->toContain($why);
})->with([
    'none' => [['access_token' => 'x'], 'no ID token'],
    'not a JWS' => [['access_token' => 'x', 'id_token' => 'not-a-token'], 'unreadable: It is not a signed JWT'],
]);

it('refuses a provider whose metadata is wrong or can\'t be read', function (Closure $break, string $why) {
    $idp = new FakeIdentityProvider()->register();
    $break($idp);

    [$reason, $message] = ssoFailure(fn () => ssoStart());

    expect($reason)->toBe(SsoFailure::Unavailable)->and($message)->toContain($why)
        ->and(session()->get('keyring.sso'))->toBeNull();
})->with([
    'down' => [fn (FakeIdentityProvider $idp) => $idp->down(), 'could not be read'],
    'another issuer' => [fn (FakeIdentityProvider $idp) => $idp->withDiscovery(['issuer' => 'https://evil.test']), 'for another issuer'],
    'no issuer' => [fn (FakeIdentityProvider $idp) => $idp->withDiscovery(['issuer' => null]), 'for another issuer'],
    'a plain HTTP endpoint' => [fn (FakeIdentityProvider $idp) => $idp->withDiscovery(['authorization_endpoint' => 'http://idp.test/authorize']), 'no HTTPS authorization_endpoint'],
    'no endpoint' => [fn (FakeIdentityProvider $idp) => $idp->withDiscovery(['authorization_endpoint' => null]), 'no HTTPS authorization_endpoint'],
]);

it('refuses endpoints on this machine, or over plain HTTP, from an issuer elsewhere', function (string $key, string $url) {
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery([$key => $url]);

    expect(ssoFailure(fn () => ssoStart()))->toBe([SsoFailure::Unavailable, "Single sign-on failed (unavailable): [fake]'s discovery document has no HTTPS {$key}."]);

    Http::assertNotSent(fn (ClientRequest $request) => str_contains($request->url(), 'localhost') || str_contains($request->url(), '127.0.0.1'));
})->with([
    'plain HTTP to localhost' => ['token_endpoint', 'http://localhost/token'],
    'HTTPS to 127.0.0.1' => ['jwks_uri', 'https://127.0.0.1/keys'],
    'HTTPS to [::1]' => ['authorization_endpoint', 'https://[::1]/authorize'],
]);

it('lets an issuer on this machine name endpoints there', function () {
    $idp = new FakeIdentityProvider('http://localhost:8080/realms/app')->register();

    expect(ssoComplete($idp->approve(ssoStart()))->issuer)->toBe('http://localhost:8080/realms/app');
});

it('keeps no discovery document it refuses, and asks again next time', function () {
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery(['issuer' => 'https://evil.test']);

    expect(ssoFailure(fn () => ssoStart())[0])->toBe(SsoFailure::Unavailable)
        ->and(ssoFailure(fn () => ssoStart())[0])->toBe(SsoFailure::Unavailable)
        ->and($idp->discoveryFetches)->toBe(2);

    $idp->withDiscovery(['issuer' => 'https://idp.test']);
    ssoStart();
    ssoStart();

    expect($idp->discoveryFetches)->toBe(3);
});

it('keeps no key set without a key in it, and asks again next time', function () {
    $idp = new FakeIdentityProvider()->register();
    Http::fake(['https://idp.test/other-keys' => Http::sequence()->push(['keys' => [1, 2]])->push(['keys' => $idp->jwks()])]);
    $idp->withDiscovery(['jwks_uri' => 'https://idp.test/other-keys']);

    expect(ssoFailure(fn () => ssoComplete($idp->approve(ssoStart())))[1])->toContain('did not list any keys')
        ->and(ssoComplete($idp->approve(ssoStart()))->subject)->toBe('248289761001');
});

it('refuses a sign in when the provider\'s keys can\'t be read', function (Closure $break, string $why) {
    $idp = new FakeIdentityProvider()->register();
    $url = ssoStart();
    $break($idp);

    [$reason, $message] = ssoFailure(fn () => ssoComplete($idp->approve($url)));

    expect($reason)->toBe(SsoFailure::Unavailable)->and($message)->toContain($why);
})->with([
    'down' => [fn (FakeIdentityProvider $idp) => $idp->down(), 'could not be read'],
    'not listed' => [function (FakeIdentityProvider $idp) {
        Http::fake(['https://idp.test/other-keys' => Http::response(['keys' => 'none'])]);
        $idp->withDiscovery(['jwks_uri' => 'https://idp.test/other-keys']);
        Cache::flush();
    }, 'did not list any keys'],
    'a list, not an object' => [function (FakeIdentityProvider $idp) {
        Http::fake(['https://idp.test/other-keys' => Http::response([1, 2])]);
        $idp->withDiscovery(['jwks_uri' => 'https://idp.test/other-keys']);
        Cache::flush();
    }, 'did not answer with a JSON object'],
]);

it('only reads metadata over HTTPS, or plain HTTP on this machine', function () {
    expect(Metadata::isSecure('https://idp.test'))->toBeTrue()
        ->and(Metadata::isSecure('http://localhost:8080/realms/app'))->toBeTrue()
        ->and(Metadata::isSecure('http://127.0.0.1/'))->toBeTrue()
        ->and(Metadata::isSecure('http://[::1]:8080'))->toBeTrue()
        ->and(Metadata::isSecure('http://idp.test'))->toBeFalse()
        ->and(Metadata::isSecure('http://localhost.evil.test'))->toBeFalse()
        ->and(Metadata::isSecure('ftp://idp.test'))->toBeFalse()
        ->and(Metadata::isSecure('not a url'))->toBeFalse()
        ->and(Metadata::isSecure(null))->toBeFalse()
        ->and(Metadata::isSecure('https://idp.test', local: false))->toBeTrue()
        ->and(Metadata::isSecure('https://localhost/keys', local: false))->toBeFalse()
        ->and(Metadata::isSecure('http://localhost:8080/keys', local: false))->toBeFalse()
        ->and(ssoFailure(fn () => app(Metadata::class)->fetch('http://idp.test/.well-known/openid-configuration')))
        ->toBe([SsoFailure::Unavailable, 'Single sign-on failed (unavailable): [http://idp.test/.well-known/openid-configuration] is not an HTTPS URL.']);
});

it('follows no redirect from a provider', function () {
    Http::fake(['https://idp.test/*' => Http::response(null, 302, ['Location' => 'https://evil.test/'])]);

    expect(ssoFailure(fn () => app(Metadata::class)->fetch('https://idp.test/.well-known/openid-configuration'))[0])->toBe(SsoFailure::Unavailable);

    Http::assertNotSent(fn (ClientRequest $request) => str_starts_with($request->url(), 'https://evil.test'));
});

it('never puts the code or tokens in what it says went wrong', function () {
    $idp = new FakeIdentityProvider()->register();
    $url = ssoStart();
    $idp->withClaims(['aud' => 'someone-else']);
    $callback = $idp->approve($url);
    $code = authorizationQuery($callback)['code'];

    [, $message] = ssoFailure(fn () => ssoComplete($callback));

    expect($message)->not->toContain($code)->not->toContain('fake-access-')->not->toContain('eyJ');
});
