<?php

declare(strict_types=1);

use Keyring\Sso\SignedToken;
use Keyring\Testing\FakeIdentityProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * A token with this header and signature, and claims nobody checks.
 *
 * @param  array<string, mixed>  $header
 */
function tokenWith(array $header, string $signature): SignedToken
{
    return SignedToken::parse(Base64UrlSafe::encodeUnpadded(json_encode($header)).'.'.Base64UrlSafe::encodeUnpadded('{"sub":"1"}').'.'.Base64UrlSafe::encodeUnpadded($signature));
}

it('checks a signature against the key that made it', function (string $algorithm) {
    $idp = new FakeIdentityProvider(algorithm: $algorithm);
    $token = SignedToken::parse($idp->idToken(['sub' => '1']));
    [$key] = $idp->jwks();

    expect($token->signedBy($key))->toBeTrue()
        ->and($token->algorithm())->toBe($algorithm)
        ->and($token->keyId())->toBe($key['kid'])
        ->and($token->claims)->toBe(['sub' => '1'])
        ->and($token->signedBy(new FakeIdentityProvider(algorithm: $algorithm)->jwks()[0]))->toBeFalse();
})->with(['ES256', 'RS256', 'PS256', 'EdDSA']);

it('takes Ed25519 as RFC 9864 names EdDSA', function () {
    $idp = new FakeIdentityProvider(algorithm: 'EdDSA');
    $token = SignedToken::parse($idp->withHeader(['alg' => 'Ed25519'])->idToken(['sub' => '1']));

    expect($token->signedBy([...$idp->jwks()[0], 'alg' => 'Ed25519']))->toBeTrue();
});

it('refuses a key that is not for signing this way', function (array $changes) {
    $idp = new FakeIdentityProvider;
    $token = SignedToken::parse($idp->idToken(['sub' => '1']));

    expect($token->signedBy(array_filter([...$idp->jwks()[0], ...$changes], fn ($value) => $value !== null)))->toBeFalse();
})->with([
    'another algorithm' => [['alg' => 'ES384']],
    'for encryption' => [['use' => 'enc']],
    'operations without verify' => [['key_ops' => ['encrypt']]],
    'operations that aren\'t a list' => [['key_ops' => 'verify']],
    'another key type' => [['kty' => 'RSA']],
    'another curve' => [['crv' => 'P-384']],
    'no x' => [['x' => null]],
    'a coordinate that isn\'t base64url' => [['x' => '***']],
    'a coordinate of the wrong length' => [['x' => Base64UrlSafe::encodeUnpadded(str_repeat("\1", 31))]],
    'a point off the curve' => [['y' => Base64UrlSafe::encodeUnpadded(str_repeat("\1", 32))]],
]);

it('takes a key that allows verifying, and says nothing of its use', function () {
    $idp = new FakeIdentityProvider;
    $token = SignedToken::parse($idp->idToken(['sub' => '1']));
    $key = $idp->jwks()[0];
    unset($key['use'], $key['alg'], $key['kid']);

    expect($token->signedBy([...$key, 'key_ops' => ['verify']]))->toBeTrue();
});

it('refuses RSA keys that aren\'t RSA, or are too short', function () {
    $idp = new FakeIdentityProvider(algorithm: 'RS256');
    $token = SignedToken::parse($idp->idToken(['sub' => '1']));
    [$key] = $idp->jwks();

    $short = openssl_pkey_get_details(openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]))['rsa'];

    expect($token->signedBy([...$key, 'kty' => 'EC']))->toBeFalse()
        ->and($token->signedBy([...$key, 'n' => null]))->toBeFalse()
        ->and($token->signedBy([...$key, 'n' => Base64UrlSafe::encodeUnpadded($short['n'])]))->toBeFalse();

    // Passkeys' floor is their own: raised for them, a provider's 2048-bit
    // key, as Google and Microsoft sign with, still checks.
    config(['keyring.webauthn.minimum_rsa_bits' => 3072]);

    expect(strlen(Base64UrlSafe::decodeNoPadding($key['n'])) * 8)->toBe(SignedToken::SHORTEST_RSA_KEY)
        ->and($token->signedBy($key))->toBeTrue();
});

it('refuses Ed25519 keys and signatures of the wrong size, or on another curve', function () {
    $idp = new FakeIdentityProvider(algorithm: 'EdDSA');
    [$key] = $idp->jwks();

    expect(SignedToken::parse($idp->idToken(['sub' => '1']))->signedBy([...$key, 'crv' => 'X25519']))->toBeFalse()
        ->and(SignedToken::parse($idp->idToken(['sub' => '1']))->signedBy([...$key, 'x' => Base64UrlSafe::encodeUnpadded('short')]))->toBeFalse()
        ->and(tokenWith(['alg' => 'EdDSA'], str_repeat("\1", 63))->signedBy($key))->toBeFalse();
});

it('refuses ES256 signatures of the wrong size, or with a zero in them', function () {
    $idp = new FakeIdentityProvider;
    [$key] = $idp->jwks();

    expect(tokenWith(['alg' => 'ES256'], str_repeat("\1", 70))->signedBy($key))->toBeFalse()
        ->and(tokenWith(['alg' => 'ES256'], str_repeat("\0", 32).str_repeat("\1", 32))->signedBy($key))->toBeFalse()
        ->and(tokenWith(['alg' => 'ES256'], str_repeat("\1", 32).str_repeat("\0", 32))->signedBy($key))->toBeFalse()
        ->and(tokenWith(['alg' => 'ES256'], str_repeat("\xFF", 64))->signedBy($key))->toBeFalse();
});

it('refuses tokens that aren\'t signed JWTs', function (string $token, string $why) {
    expect(fn () => SignedToken::parse($token))->toThrow(InvalidArgumentException::class, $why);
})->with([
    'two parts' => ['eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0', 'compact form'],
    'four parts' => ['a.b.c.d', 'compact form'],
    'padding' => ['eyJhbGciOiJSUzI1NiJ9=.eyJzdWIiOiIxIn0.', 'compact form'],
    'too long' => [str_repeat('a', 16 * 1024).'.b.c', 'compact form'],
    'a trailing newline' => ["eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.\n", 'compact form'],
    'not base64url' => ['a.eyJzdWIiOiIxIn0.', 'not base64url'],
    'not JSON' => [Base64UrlSafe::encodeUnpadded('nope').'.eyJzdWIiOiIxIn0.', 'not hold JSON'],
    'a JSON list' => [Base64UrlSafe::encodeUnpadded('["RS256"]').'.eyJzdWIiOiIxIn0.', 'not hold a JSON object'],
    'a JSON string' => [Base64UrlSafe::encodeUnpadded('{"alg":"RS256"}').'.'.Base64UrlSafe::encodeUnpadded('"sub"').'.', 'not hold a JSON object'],
    'nested too deep' => [Base64UrlSafe::encodeUnpadded(str_repeat('[', 40).str_repeat(']', 40)).'.eyJzdWIiOiIxIn0.', 'not hold JSON'],
]);

it('checks the fake\'s authorization requests as a provider would', function (string $url, string $why) {
    expect(fn () => new FakeIdentityProvider()->approve($url))->toThrow(InvalidArgumentException::class, $why);
})->with([
    'another endpoint' => ['https://evil.test/authorize?client_id=x', 'not this provider\'s authorization endpoint'],
    'no PKCE' => ['https://idp.test/authorize?response_type=code&client_id='.FakeIdentityProvider::CLIENT_ID.'&redirect_uri=x&state='.str_repeat('a', 43).'&nonce=n', 'no S256 code challenge'],
    'form_post' => ['https://idp.test/authorize?response_type=code&client_id='.FakeIdentityProvider::CLIENT_ID.'&redirect_uri=x&state='.str_repeat('a', 43).'&nonce=n&code_challenge=c&code_challenge_method=S256&response_mode=form_post', 'another response_mode'],
    'another client' => ['https://idp.test/authorize?response_type=code&client_id=other', 'client_id is not'],
    'no state' => ['https://idp.test/authorize?response_type=code&client_id='.FakeIdentityProvider::CLIENT_ID.'&redirect_uri=x', 'no state'],
    'no nonce' => ['https://idp.test/authorize?response_type=code&client_id='.FakeIdentityProvider::CLIENT_ID.'&redirect_uri=x&state='.str_repeat('a', 43).'&code_challenge=c&code_challenge_method=S256', 'no nonce'],
    'no redirect' => ['https://idp.test/authorize?response_type=code&client_id='.FakeIdentityProvider::CLIENT_ID, 'no redirect_uri'],
    'implicit' => ['https://idp.test/authorize?response_type=token', 'response_type is not "code"'],
]);
