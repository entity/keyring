<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Http;
use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\UnknownSsoProvider;
use Keyring\Facades\Keyring;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\PendingAuthorizations;
use Keyring\Support\EncryptedSession;
use Keyring\Testing\FakeIdentityProvider;

// Nothing here may reach a real provider.
beforeEach(fn () => Http::preventStrayRequests());

it('gives back the purpose and data the sign in was started with', function () {
    $idp = new FakeIdentityProvider()->register();

    $identity = ssoComplete($idp->approve(ssoStart(purpose: 'link', data: ['user' => 7, 'remember' => true])));

    expect($identity->request->purpose)->toBe('link')
        ->and($identity->request->data)->toBe(['user' => 7, 'remember' => true])
        ->and($identity->request->redirectUri)->toBe(SSO_CALLBACK)
        ->and($identity->request->provider)->toBe('fake');
});

it('keeps the request in the session, encrypted, and nothing of it in the URL but its state', function () {
    $idp = new FakeIdentityProvider()->register();

    $url = ssoStart(purpose: 'link', data: ['user' => 7]);
    $stored = session()->get('keyring.sso');

    expect($stored)->toBeString()
        ->and(Crypt::decryptString($stored))->toContain('code_verifier')
        ->and($url)->not->toContain('link')
        ->and($url)->not->toContain(array_first(json_decode(Crypt::decryptString($stored), true))['code_verifier']);
});

it('takes a state once, and a callback used again is refused', function () {
    $idp = new FakeIdentityProvider()->register();
    $callback = $idp->approve(ssoStart());

    ssoComplete($callback);

    expect(ssoFailure(fn () => ssoComplete($callback))[0])->toBe(SsoFailure::InvalidState);
});

it('spends the state even when the sign in fails', function () {
    $idp = new FakeIdentityProvider()->register();
    $url = ssoStart();
    $callback = $idp->withClaims(['aud' => 'someone-else'])->approve($url);

    expect(ssoFailure(fn () => ssoComplete($callback))[0])->toBe(SsoFailure::InvalidToken);

    $idp->withClaims(['aud' => FakeIdentityProvider::CLIENT_ID]);

    expect(ssoFailure(fn () => ssoComplete($idp->approve($url)))[0])->toBe(SsoFailure::InvalidState)
        ->and(ssoFailure(fn () => ssoComplete($idp->deny(ssoStart())))[0])->toBe(SsoFailure::Denied);
});

it('refuses a state it was never given, or none', function (string $query) {
    new FakeIdentityProvider()->register();
    ssoStart();

    expect(ssoFailure(fn () => ssoComplete(SSO_CALLBACK.'?code=abc'.$query))[0])->toBe(SsoFailure::InvalidState);
})->with([
    'unknown' => ['&state='.str_repeat('a', 43)],
    'missing' => [''],
    'empty' => ['&state='],
    'an array' => ['&state[]=a'],
]);

it('refuses a state once its request has expired', function () {
    $idp = new FakeIdentityProvider()->register();
    $callback = $idp->approve(ssoStart());

    $this->travel(11)->minutes();

    expect(ssoFailure(fn () => ssoComplete($callback))[0])->toBe(SsoFailure::InvalidState);
});

it('lasts as long as the config says', function () {
    config(['keyring.sso.request_for' => '1m']);
    $idp = new FakeIdentityProvider()->register();
    $callback = $idp->approve(ssoStart());

    $this->travel(2)->minutes();

    expect(ssoFailure(fn () => ssoComplete($callback))[0])->toBe(SsoFailure::InvalidState);
});

it('refuses a state started for another provider, and spends it', function () {
    $idp = new FakeIdentityProvider()->register();
    new FakeIdentityProvider('https://other.test')->register('other');
    $callback = $idp->approve(ssoStart());

    expect(ssoFailure(fn () => ssoComplete($callback, 'other')))->toBe([SsoFailure::InvalidState, 'Single sign-on failed (invalid_state): The callback for [other] has the state of a sign in with [fake].'])
        ->and(ssoFailure(fn () => ssoComplete($callback))[0])->toBe(SsoFailure::InvalidState);
});

it('keeps a few requests at once, and lets the newest push out the oldest', function () {
    $idp = new FakeIdentityProvider()->register();

    $urls = collect(range(1, PendingAuthorizations::MAX + 1))->map(fn () => ssoStart());

    expect(ssoFailure(fn () => ssoComplete($idp->approve($urls->first())))[0])->toBe(SsoFailure::InvalidState);

    $urls->slice(1)->each(fn (string $url) => expect(ssoComplete($idp->approve($url))->subject)->toBe('248289761001'));

    expect(session()->has('keyring.sso'))->toBeFalse();
});

it('drops expired requests when a new one is kept', function () {
    $idp = new FakeIdentityProvider()->register();
    ssoStart();

    $this->travel(11)->minutes();
    ssoStart();

    expect(json_decode(Crypt::decryptString(session()->get('keyring.sso')), true))->toHaveCount(1);
});

it('refuses a state a copy of the session brings back', function () {
    $idp = new FakeIdentityProvider()->register();
    $url = ssoStart();
    $copy = session()->get('keyring.sso');
    $callback = $idp->approve($url);

    ssoComplete($callback);

    // Where the browser holds the session, it can send the old one again.
    session()->put('keyring.sso', $copy);

    expect(ssoFailure(fn () => ssoComplete($idp->approve($url)))[0])->toBe(SsoFailure::InvalidState);
});

it('passes over requests in the session it can\'t read', function () {
    $idp = new FakeIdentityProvider()->register();

    app(EncryptedSession::class)->put('keyring.sso', ['broken' => ['state' => 'broken'], 'worse' => 'nothing']);
    $callback = $idp->approve(ssoStart());

    expect(ssoComplete($callback)->subject)->toBe('248289761001')
        ->and(ssoFailure(fn () => ssoComplete(SSO_CALLBACK.'?code=x&state=broken'))[0])->toBe(SsoFailure::InvalidState);
});

it('makes secrets PKCE allows, and a challenge from the verifier', function () {
    $request = AuthorizationRequest::make('fake', 'login', SSO_CALLBACK);

    expect($request->state)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($request->nonce)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($request->codeVerifier)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($request->codeChallenge())->toBe(rtrim(strtr(base64_encode(hash('sha256', $request->codeVerifier, true)), '+/', '-_'), '='))
        ->and(AuthorizationRequest::fromArray($request->toArray()))->toEqual($request)
        ->and($request->expired)->toBeFalse();
});

it('keeps nothing when the provider isn\'t configured', function () {
    expect(fn () => Keyring::sso()->start('missing', 'login', SSO_CALLBACK))->toThrow(UnknownSsoProvider::class)
        ->and(session()->has('keyring.sso'))->toBeFalse();
});
