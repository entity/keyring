<?php

declare(strict_types=1);

use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Keyring\Enums\SsoFailure;
use Keyring\Facades\Keyring;
use Keyring\Sso\HostResolver;
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

it('sends only its ID as a public client', function (array $config) {
    $idp = new FakeIdentityProvider()->register(config: $config);

    ssoComplete($idp->approve(ssoStart()));

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://idp.test/token'
        && $request['client_id'] === FakeIdentityProvider::CLIENT_ID
        && ! isset($request['client_secret'])
        && ! $request->hasHeader('Authorization'));
})->with([
    'without a secret' => [['client_secret' => null]],
    'with a secret, but the auth method none' => [['token_endpoint_auth_method' => 'none']],
]);

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

    expect(ssoFailure(fn () => Keyring::sso()->complete($request, 'fake'))[0])->toBe(SsoFailure::InvalidState);
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

it('refuses endpoints over plain HTTP from an issuer elsewhere', function (string $key) {
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery([$key => 'http://localhost/'.$key]);

    expect(ssoFailure(fn () => ssoStart()))->toBe([SsoFailure::Unavailable, "Single sign-on failed (unavailable): [fake]'s discovery document has no HTTPS {$key}."]);

    Http::assertNotSent(fn (ClientRequest $request) => str_contains($request->url(), 'localhost'));
})->with(['authorization_endpoint', 'token_endpoint', 'jwks_uri']);

it('refuses an endpoint whose host is percent-encoded, which the HTTP client would decode', function (string $key, string $url) {
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery([$key => $url]);

    expect(ssoFailure(fn () => ssoStart()))->toBe([SsoFailure::Unavailable, "Single sign-on failed (unavailable): [fake]'s discovery document has no HTTPS {$key}."]);

    Http::assertNotSent(fn (ClientRequest $request) => ! str_starts_with($request->url(), 'https://idp.test/'));
})->with([
    'an address' => ['token_endpoint', 'https://10.0.0.%31/token'],
    'a name' => ['jwks_uri', 'https://intern%61l.example.com/keys'],
]);

it('refuses endpoints it sends requests to on this machine or inside the network, from an issuer elsewhere', function (string $key, string $url) {
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery([$key => $url]);

    expect(ssoFailure(fn () => ssoStart()))->toBe([SsoFailure::Unavailable, "Single sign-on failed (unavailable): [fake]'s discovery document names {$key} on a private or local address. Set \"private_endpoints\" if that's where it is."]);

    Http::assertNotSent(fn (ClientRequest $request) => ! str_starts_with($request->url(), 'https://idp.test/'));
})->with([
    'HTTPS to localhost' => ['token_endpoint', 'https://localhost/token'],
    'HTTPS to 127.0.0.1' => ['jwks_uri', 'https://127.0.0.1/keys'],
    'HTTPS to [::1]' => ['token_endpoint', 'https://[::1]/token'],
    'the unspecified IPv6 address' => ['token_endpoint', 'https://[::]/token'],
    'the rest of 127.0.0.0/8' => ['token_endpoint', 'https://127.0.0.2/token'],
    '0.0.0.0' => ['token_endpoint', 'https://0.0.0.0/token'],
    'localhost with a trailing dot' => ['token_endpoint', 'https://localhost./token'],
    'an address with a trailing dot' => ['token_endpoint', 'https://127.0.0.1./token'],
    'LOCALHOST' => ['token_endpoint', 'https://LOCALHOST/token'],
    'a name under localhost' => ['token_endpoint', 'https://idp.localhost/token'],
    'IPv4 inside IPv6' => ['token_endpoint', 'https://[::ffff:127.0.0.1]/token'],
    'IPv4-compatible IPv6' => ['token_endpoint', 'https://[::7f00:1]/token'],
    'a private address' => ['token_endpoint', 'https://10.0.0.5/token'],
    'another private range' => ['jwks_uri', 'https://192.168.1.10/keys'],
    'the cloud metadata address' => ['token_endpoint', 'https://169.254.169.254/latest/meta-data'],
    'carrier-grade NAT' => ['token_endpoint', 'https://100.64.0.1/token'],
    'IPv4 multicast' => ['token_endpoint', 'https://224.0.0.1/token'],
    'IPv6 link-local' => ['token_endpoint', 'https://[fe80::1]/token'],
    'IPv6 unique local' => ['token_endpoint', 'https://[fd00::1]/token'],
    'IPv6 site-local' => ['token_endpoint', 'https://[fec0::1]/token'],
    'IPv6 multicast' => ['token_endpoint', 'https://[ff0e::1]/token'],
    'the metadata address through NAT64' => ['token_endpoint', 'https://[64:ff9b::a9fe:a9fe]/token'],
    'the local-use NAT64 prefix' => ['token_endpoint', 'https://[64:ff9b:1::a9fe:a9fe]/token'],
    'an address written as one number' => ['token_endpoint', 'https://2130706433/token'],
    'an address written in hex' => ['token_endpoint', 'https://0x7f.1/token'],
    'an address written in octal' => ['token_endpoint', 'https://0177.0.0.1/token'],
    'an address with parts left out' => ['token_endpoint', 'https://127.1/token'],
]);

it('refuses a userinfo endpoint inside the network when a driver reads it', function () {
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery(['userinfo_endpoint' => 'https://10.0.0.5/userinfo']);
    $provider = Keyring::sso()->provider('fake');

    expect(ssoFailure(fn () => (fn () => $this->endpoint('userinfo_endpoint'))->call($provider))[1])->toContain('names userinfo_endpoint on a private or local address');
});

it('lets an authorization endpoint be anywhere over HTTPS, since only the browser goes there', function (string $url) {
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery(['authorization_endpoint' => $url]);

    expect(ssoStart())->toStartWith($url.'?');
})->with(['https://[::1]/authorize', 'https://10.0.0.5/authorize', 'https://sso/authorize']);

it('refuses endpoints whose name resolves inside the network, from an issuer elsewhere', function (array $addresses) {
    HostResolver::fake(['inside.example.com' => $addresses]);
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery(['token_endpoint' => 'https://inside.example.com/token']);

    expect(ssoFailure(fn () => ssoStart()))->toBe([SsoFailure::Unavailable, "Single sign-on failed (unavailable): [fake]'s discovery document names token_endpoint on a private or local address. Set \"private_endpoints\" if that's where it is."]);

    Http::assertNotSent(fn (ClientRequest $request) => str_contains($request->url(), 'inside.example.com'));
})->with([
    'loopback' => [['127.0.0.1']],
    'a private address' => [['10.1.2.3']],
    'the metadata address' => [['169.254.169.254']],
    'IPv6 loopback' => [['::1']],
    'a public address beside a private one' => [['93.184.216.34', '192.168.0.1']],
]);

it('takes endpoints whose name resolves to public addresses, or not at all', function (array $addresses) {
    HostResolver::fake(['idp.test' => $addresses]);
    $idp = new FakeIdentityProvider()->register();

    expect(ssoComplete($idp->approve(ssoStart()))->subject)->toBe('248289761001');
})->with([
    'public addresses' => [['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946']],
    'a public address through NAT64' => [['64:ff9b::5db8:d822']],
    'nothing' => [[]],
]);

it('refuses a name without a dot that doesn\'t resolve, and takes one that resolves to a public address', function () {
    HostResolver::fake(['sso' => ['93.184.216.34']]);
    $idp = new FakeIdentityProvider()->register();

    $idp->withDiscovery(['token_endpoint' => 'https://ip6-localhost/token']);
    expect(ssoFailure(fn () => ssoStart())[1])->toContain('names token_endpoint on a private or local address');

    $idp->withDiscovery(['token_endpoint' => 'https://sso/token']);
    expect(ssoStart())->toStartWith('https://idp.test/authorize?');
});

it('lets an issuer inside the network name endpoints on its own host and port', function () {
    HostResolver::fake(['keycloak.corp.example' => ['10.0.0.5'], 'keycloak' => []]);
    $idp = new FakeIdentityProvider('https://keycloak.corp.example/realms/app')->register();

    expect(ssoComplete($idp->approve(ssoStart()))->issuer)->toBe('https://keycloak.corp.example/realms/app');

    $dotless = new FakeIdentityProvider('https://keycloak/realms/app')->register('dotless');

    expect(ssoComplete($dotless->approve(ssoStart('dotless')), 'dotless')->issuer)->toBe('https://keycloak/realms/app');
});

it('still refuses an issuer\'s endpoints on its host at another port, or on another host inside the network', function (string $url) {
    HostResolver::fake(['keycloak.corp.example' => ['10.0.0.5'], 'admin.corp.example' => ['10.0.0.6']]);
    $idp = new FakeIdentityProvider('https://keycloak.corp.example/realms/app')->register();
    $idp->withDiscovery(['token_endpoint' => $url]);

    expect(ssoFailure(fn () => ssoStart())[1])->toContain('names token_endpoint on a private or local address');
})->with(['https://keycloak.corp.example:8443/token', 'https://admin.corp.example/token', 'https://10.0.0.5/token']);

it('lets a provider with private_endpoints name endpoints anywhere over HTTPS', function () {
    HostResolver::fake(['idp.test' => ['240.240.0.1']]);
    $idp = new FakeIdentityProvider()->register(config: ['private_endpoints' => true]);
    Http::fake(['https://10.0.0.9/keys' => Http::response(['keys' => $idp->jwks()])]);
    $idp->withDiscovery(['jwks_uri' => 'https://10.0.0.9/keys']);

    expect(ssoComplete($idp->approve(ssoStart()))->subject)->toBe('248289761001');

    Http::assertSent(fn (ClientRequest $request) => $request->url() === 'https://10.0.0.9/keys');

    $idp->withDiscovery(['jwks_uri' => 'http://10.0.0.9/keys']);
    Cache::flush();

    expect(ssoFailure(fn () => ssoStart())[1])->toContain('has no HTTPS jwks_uri');
});

it('refuses private_endpoints that isn\'t true or false', function (mixed $value) {
    new FakeIdentityProvider()->register(config: ['private_endpoints' => $value]);

    expect(fn () => Keyring::sso()->provider('fake'))->toThrow(InvalidArgumentException::class, 'Identity provider [fake] has a "private_endpoints" that isn\'t true or false.');
})->with(['a string' => 'true', 'a number' => 1]);

it('looks each host up once for a sign in', function () {
    $lookups = [];
    app()->instance(HostResolver::class, new HostResolver(function (string $host) use (&$lookups) {
        $lookups[] = $host;

        return [];
    }));
    $idp = new FakeIdentityProvider()->register();
    $idp->withDiscovery(['jwks_uri' => 'https://keys.idp.test/keys']);
    Http::fake(['https://keys.idp.test/keys' => Http::response(['keys' => $idp->jwks()])]);

    ssoComplete($idp->approve(ssoStart()));

    expect($lookups)->toBe(['keys.idp.test']);
});

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
        ->and(Metadata::isSecure('https://localhost/keys', local: false))->toBeTrue()
        ->and(Metadata::isSecure('http://localhost:8080/keys', local: false))->toBeFalse()
        ->and(Metadata::isSecure('http://localhost.:8080/realms/app'))->toBeTrue()
        ->and(Metadata::isInward('https://127.0.0.2/keys'))->toBeTrue()
        ->and(Metadata::isInward('https://93.184.216.34/keys'))->toBeFalse()
        ->and(Metadata::isInward('https://10.0.0.%31/token'))->toBeTrue()
        ->and(Metadata::isInward('https://169.254.169.25%34/keys'))->toBeTrue()
        ->and(Metadata::isInward('https://intern%61l.example.com/token'))->toBeTrue()
        ->and(Metadata::isInward('https://ïdp.example.com/token'))->toBeTrue()
        ->and(Metadata::isInward('https://xn--dp-yia.example.com/token'))->toBeFalse()
        ->and(Metadata::isInward('https://[2606:2800:220:1:248:1893:25c8:1946]/keys'))->toBeFalse()
        ->and(Metadata::sameHost('https://idp.test/token', 'https://IDP.test.:443/'))->toBeTrue()
        ->and(Metadata::sameHost('http://idp.test/token', 'http://idp.test:80/'))->toBeTrue()
        ->and(Metadata::sameHost('ftp://idp.test/token', 'ftp://idp.test/'))->toBeTrue()
        ->and(Metadata::sameHost('https://idp.test/token', 'http://idp.test/'))->toBeFalse()
        ->and(Metadata::sameHost('https://idp.test:8443/token', 'https://idp.test/'))->toBeFalse()
        ->and(Metadata::sameHost('https://keys.idp.test/', 'https://idp.test/'))->toBeFalse()
        ->and(Metadata::isLocal('http://LOCALHOST./'))->toBeTrue()
        ->and(Metadata::isLocal('http://[::1]:8080/'))->toBeTrue()
        ->and(Metadata::isLocal('http://127.0.0.2/'))->toBeFalse()
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
