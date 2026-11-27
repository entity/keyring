<?php

declare(strict_types=1);

namespace Keyring\Testing;

use DateTimeInterface;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Keyring\Sso\HostResolver;
use Keyring\Sso\Providers\GitHubProvider;
use Keyring\Sso\Providers\GoogleProvider;
use Keyring\Sso\Providers\MicrosoftProvider;
use OpenSSLAsymmetricKey;
use ParagonIE\ConstantTime\Base64UrlSafe;
use RuntimeException;

/**
 * An identity provider for tests. It answers Keyring's requests through
 * Http::fake() as the real one would: discovery, signing keys, the token
 * endpoint and, for GitHub, its user API. Its ID tokens are really signed,
 * with keys it makes, so every check Keyring runs on them runs in the test.
 *
 *     $idp = FakeIdentityProvider::google()->register('google');
 *
 *     $url = Keyring::sso()->start('google', 'login', 'https://app.test/sso/google/callback');
 *     $callback = $idp->signIn(['sub' => '42', 'email' => 'taylor@example.com'])->approve($url);
 *
 *     $this->get($callback);
 *
 * approve() checks the authorization URL the way the provider would (its
 * client ID, a PKCE S256 challenge, a state, and a nonce for OpenID
 * Connect) and gives back the callback URL. The token endpoint only swaps
 * the code for tokens once, with the right verifier, redirect URI and
 * client credentials.
 *
 * Its ID tokens say when the user signed in there (auth_time): the first
 * time they're approved, and again whenever a request asks for a new sign
 * in (prompt=login, or a max_age they're past). In between it lets them
 * straight through on that session, as a provider does. signedInAt() gives
 * them a session from earlier, ignoringReauthentication() keeps using it
 * when asked not to, and withClaims(['auth_time' => null]) leaves it out.
 * As Google does, the fake Google only sends auth_time when the claims
 * parameter asks for it. As Microsoft does, the fake Microsoft only sends
 * it with the optional claim: withAuthTimeClaim().
 *
 * To test what Keyring refuses, change what the next tokens are:
 * withClaims(['aud' => 'someone-else']), expired(), unsigned(),
 * signedWithPublicKeyAsSecret(), signedWithUnpublishedKey(), or
 * rotateKeys() to sign with a key Keyring hasn't cached yet.
 *
 * Make it before any catch-all Http::fake() of the test's own, which would
 * otherwise answer its requests first.
 */
class FakeIdentityProvider
{
    public const string CLIENT_ID = 'keyring-test-client';

    public const string CLIENT_SECRET = 'keyring-test-secret';

    /**
     * How often Keyring has read its discovery document and its keys.
     */
    public protected(set) int $discoveryFetches = 0;

    public protected(set) int $keyFetches = 0;

    /**
     * Who signs in next: the ID token's claims, or GitHub's user.
     *
     * @var array<string, mixed>
     */
    protected array $user;

    /**
     * GitHub's list of the user's addresses.
     *
     * @var list<array<string, mixed>>
     */
    protected array $emails = [];

    /**
     * The keys it has made, the last one signing, and the IDs of those its
     * key set lists.
     *
     * @var array<string, OpenSSLAsymmetricKey|non-empty-string>
     */
    protected array $keys = [];

    /** @var list<string> */
    protected array $published = [];

    /**
     * When the user last signed in at it, or null before they first have.
     */
    public protected(set) ?int $authenticatedAt = null;

    protected bool $ignoresReauthentication = false;

    /**
     * Whether the fake Microsoft sends auth_time, as the real one only does
     * once the app registration adds it as an optional claim.
     */
    protected bool $sendsAuthTimeClaim = false;

    /**
     * Codes handed out and not yet swapped for tokens.
     *
     * @var array<string, array{client_id: string, redirect_uri: string, challenge: string, nonce: ?string, scope: string, auth_time: ?int}>
     */
    protected array $codes = [];

    /**
     * Access tokens handed out, which GitHub's user API takes.
     *
     * @var list<string>
     */
    protected array $accessTokens = [];

    /** @var array<string, mixed> */
    protected array $claims = [];

    /** @var array<string, mixed> */
    protected array $header = [];

    /** @var array<string, mixed> */
    protected array $discovery = [];

    /**
     * How tokens are signed: with its key, or "none", "secret" or
     * "unpublished" to be refused.
     */
    protected string $signing = 'key';

    protected bool $sendsIssuer = false;

    /** @var list<string> */
    protected array $authMethods = ['client_secret_basic', 'client_secret_post'];

    /**
     * The "issuer" its keys name, as Microsoft's do, or null for none.
     */
    protected ?string $keyIssuer = null;

    /** @var array{int, string}|null */
    protected ?array $exchangeFailure = null;

    protected bool $down = false;

    public function __construct(
        // The issuer as Keyring is configured with it.
        public readonly string $issuer = 'https://idp.test',
        public readonly string $driver = 'oidc',
        // What its keys sign with: ES256, RS256, PS256 or EdDSA.
        public readonly string $algorithm = 'ES256',
        // The tenant a Microsoft user belongs to, as its tokens' "tid".
        public readonly string $tenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47',
    ) {
        $this->user = $driver === 'github'
            ? ['id' => 583231, 'login' => 'taylor', 'name' => 'Taylor Otwell', 'email' => null]
            : ['sub' => '248289761001', 'email' => 'taylor@example.com', 'email_verified' => true, 'name' => 'Taylor Otwell'];

        $this->emails = [['email' => 'taylor@example.com', 'primary' => true, 'verified' => true, 'visibility' => 'private']];

        $this->rotateKeys();

        if ($driver === 'microsoft') {
            $this->keyIssuer = MicrosoftProvider::AUTHORITY.'/{tenantid}/v2.0';
        }

        Http::fake(fn (Request $request) => $this->answer($request));

        // Its endpoints are on hosts that don't resolve, or are real
        // providers' it stands in for: none is looked up while it does.
        if (! app()->bound(HostResolver::class)) {
            HostResolver::fake();
        }
    }

    public static function google(string $algorithm = 'RS256'): self
    {
        return new self(GoogleProvider::ISSUER, 'google', $algorithm);
    }

    /**
     * Microsoft for one tenant ("common", "organizations", "consumers", a
     * tenant ID or a domain). Its users are in $tenantId, which a tenant ID
     * given here is.
     */
    public static function microsoft(string $tenant = 'common', string $tenantId = '72f988bf-86f1-41af-91ab-2d7cd011db47'): self
    {
        $tenantId = match (true) {
            $tenant === 'consumers' => MicrosoftProvider::CONSUMERS,
            Str::isUuid($tenant) => $tenant,
            default => $tenantId,
        };

        return new self(MicrosoftProvider::AUTHORITY.'/'.$tenant.'/v2.0', 'microsoft', 'RS256', $tenantId);
    }

    public static function github(): self
    {
        return new self(GitHubProvider::ISSUER, 'github');
    }

    /**
     * Add it to keyring.sso.providers, with its client's credentials.
     *
     * @param  array<string, mixed>  $config  anything to add or change
     */
    public function register(string $name = 'fake', array $config = []): static
    {
        $base = ['driver' => $this->driver, 'client_id' => self::CLIENT_ID, 'client_secret' => self::CLIENT_SECRET];

        $base += match ($this->driver) {
            'oidc' => ['issuer' => $this->issuer],
            'microsoft' => ['tenant' => Str::between($this->issuer, MicrosoftProvider::AUTHORITY.'/', '/v2.0')],
            default => [],
        };

        config(['keyring.sso.providers.'.$name => [...$base, ...$config]]);

        return $this;
    }

    /**
     * Who signs in next. For OpenID Connect these are ID token claims, for
     * GitHub the user its API answers with (and, if given, the addresses).
     *
     * @param  array<string, mixed>  $user
     * @param  list<array<string, mixed>>|null  $emails
     */
    public function signIn(array $user, ?array $emails = null): static
    {
        $this->user = [...$this->user, ...$user];
        $this->emails = $emails ?? $this->emails;

        return $this;
    }

    /**
     * The user signed in at it at this moment, and is let straight through
     * on that session until a request asks for a new sign in.
     */
    public function signedInAt(DateTimeInterface|int $at): static
    {
        $this->authenticatedAt = $at instanceof DateTimeInterface ? $at->getTimestamp() : $at;

        return $this;
    }

    /**
     * Let the user through on the session they have even when a request
     * asks for a new sign in, as a provider that ignores prompt=login and
     * max_age would. Its auth_time then says how old the session is.
     */
    public function ignoringReauthentication(): static
    {
        $this->ignoresReauthentication = true;

        return $this;
    }

    /**
     * The callback URL for a user who signed in at the authorization URL
     * Keyring sent them to: signing in there if they hadn't, or if it asks
     * them to again.
     */
    public function approve(string $authorizationUrl): string
    {
        $query = $this->authorizationRequest($authorizationUrl);
        $code = Str::random(40);
        $now = now()->getTimestamp();

        $asked = ($query['prompt'] ?? null) === 'login'
            || (isset($query['max_age']) && $this->authenticatedAt !== null && $now - $this->authenticatedAt > (int) $query['max_age']);

        if ($this->authenticatedAt === null || ($asked && ! $this->ignoresReauthentication)) {
            $this->authenticatedAt = $now;
        }

        $this->codes[$code] = [
            'client_id' => $query['client_id'],
            'redirect_uri' => $query['redirect_uri'],
            'challenge' => $query['code_challenge'],
            'nonce' => $query['nonce'] ?? null,
            'scope' => $query['scope'] ?? '',
            'auth_time' => $this->sendsAuthTime($query) ? $this->authenticatedAt : null,
        ];

        return $this->callback($query, ['code' => $code]);
    }

    /**
     * Send auth_time from the fake Microsoft, as an app registration with
     * the auth_time optional claim has the real one do.
     */
    public function withAuthTimeClaim(): static
    {
        $this->sendsAuthTimeClaim = true;

        return $this;
    }

    /**
     * Whether the ID token for this request says when the user signed in:
     * Google's only when the claims parameter asks for it, Microsoft's only
     * with the optional claim, and any other's always.
     *
     * @param  array<string, mixed>  $query
     */
    protected function sendsAuthTime(array $query): bool
    {
        return match ($this->driver) {
            'google' => $this->asksForAuthTime($query),
            'microsoft' => $this->sendsAuthTimeClaim,
            default => true,
        };
    }

    /**
     * Whether the request's claims parameter asks for auth_time in the ID
     * token.
     *
     * @param  array<string, mixed>  $query
     */
    protected function asksForAuthTime(array $query): bool
    {
        $claims = is_string($query['claims'] ?? null) ? json_decode($query['claims'], true) : null;

        return is_array($claims) && is_array($claims['id_token'] ?? null) && array_key_exists('auth_time', $claims['id_token']);
    }

    /**
     * The callback URL for a user who said no, or for another error.
     */
    public function deny(string $authorizationUrl, string $error = 'access_denied'): string
    {
        return $this->callback($this->authorizationRequest($authorizationUrl), ['error' => $error]);
    }

    /**
     * Claims to add to the next ID tokens, or to replace. Null leaves one out.
     *
     * @param  array<string, mixed>  $claims
     */
    public function withClaims(array $claims): static
    {
        $this->claims = [...$this->claims, ...$claims];

        return $this;
    }

    /**
     * JOSE header parameters to add to the next ID tokens, or to replace.
     *
     * @param  array<string, mixed>  $header
     */
    public function withHeader(array $header): static
    {
        $this->header = [...$this->header, ...$header];

        return $this;
    }

    /**
     * Discovery document entries to add, or to replace. Null leaves one out.
     *
     * @param  array<string, mixed>  $discovery
     */
    public function withDiscovery(array $discovery): static
    {
        $this->discovery = [...$this->discovery, ...$discovery];

        return $this;
    }

    /**
     * ID tokens that ran out an hour ago.
     */
    public function expired(): static
    {
        return $this->withClaims(['iat' => now()->getTimestamp() - 7200, 'exp' => now()->getTimestamp() - 3600]);
    }

    /**
     * ID tokens with "alg": "none" and no signature.
     */
    public function unsigned(): static
    {
        $this->signing = 'none';

        return $this;
    }

    /**
     * ID tokens "signed" with HS256, using the public key as the secret:
     * what a verifier that lets the token pick its algorithm would take.
     */
    public function signedWithPublicKeyAsSecret(): static
    {
        $this->signing = 'secret';

        return $this;
    }

    /**
     * ID tokens signed with a key its key set doesn't list, under a key ID
     * it doesn't either.
     */
    public function signedWithUnpublishedKey(): static
    {
        $this->signing = 'unpublished';

        return $this;
    }

    /**
     * Sign with a new key from now on, which its key set lists from now on
     * too. The old ones stay listed unless they're retired.
     */
    public function rotateKeys(bool $retireOld = false): static
    {
        $kid = Str::random(16);
        $this->keys[$kid] = $this->makeKey();
        $this->published = $retireOld ? [$kid] : [...$this->published, $kid];

        return $this;
    }

    /**
     * Have its keys name this "issuer", as Microsoft's say which tenant's
     * tokens each one signs: its own, https://login.microsoftonline.com/{tenantid}/v2.0
     * by default, or another tenant's. Null names none.
     */
    public function withKeyIssuer(?string $issuer): static
    {
        $this->keyIssuer = $issuer;

        return $this;
    }

    /**
     * Send RFC 9207's "iss" with every callback, and say so in discovery.
     */
    public function sendsIssuer(): static
    {
        $this->sendsIssuer = true;

        return $this;
    }

    /**
     * The client authentication methods its token endpoint takes, and
     * discovery lists.
     *
     * @param  list<string>  $methods
     */
    public function authMethods(array $methods): static
    {
        $this->authMethods = $methods;

        return $this;
    }

    /**
     * Refuse every code at the token endpoint.
     */
    public function failExchange(int $status = 400, string $error = 'invalid_grant'): static
    {
        $this->exchangeFailure = [$status, $error];

        return $this;
    }

    /**
     * Answer every request for metadata, keys or the user API with a 503.
     */
    public function down(): static
    {
        $this->down = true;

        return $this;
    }

    /**
     * An ID token for these claims, signed as the next one would be.
     *
     * @param  array<string, mixed>  $claims
     */
    public function idToken(array $claims): string
    {
        $kid = array_key_last($this->keys) ?? throw new RuntimeException('It has no keys.');
        $key = $this->keys[$kid];

        if ($this->signing === 'unpublished') {
            $kid = Str::random(16);
            $key = $this->makeKey();
        }

        $algorithm = match ($this->signing) {
            'none' => 'none',
            'secret' => 'HS256',
            default => $this->algorithm,
        };

        $header = array_filter([...['alg' => $algorithm, 'typ' => 'JWT', 'kid' => $kid], ...$this->header], fn (mixed $value) => $value !== null);
        $claims = array_filter([...$claims, ...$this->claims], fn (mixed $value) => $value !== null);

        $signed = $this->encode($header).'.'.$this->encode($claims);

        $signature = match ($this->signing) {
            'none' => '',
            'secret' => hash_hmac('sha256', $signed, $this->pem($key), true),
            default => $this->sign($signed, $key),
        };

        return $signed.'.'.Base64UrlSafe::encodeUnpadded($signature);
    }

    /**
     * The public keys its key set lists.
     *
     * @return list<array<string, string>>
     */
    public function jwks(): array
    {
        return array_map(fn (string $kid) => $this->jwk($kid, $this->keys[$kid]), $this->published);
    }

    /**
     * The issuer its tokens come from: Microsoft's tenant's, or the one
     * Keyring is configured with.
     */
    public function tokenIssuer(): string
    {
        return $this->driver === 'microsoft' ? MicrosoftProvider::AUTHORITY.'/'.$this->tenantId.'/v2.0' : $this->issuer;
    }

    /**
     * @return array<string, mixed>
     */
    protected function authorizationRequest(string $url): array
    {
        if (! str_starts_with($url, $this->endpoints()['authorization_endpoint'].'?')) {
            throw new InvalidArgumentException("[{$url}] is not this provider's authorization endpoint.");
        }

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        $problem = match (true) {
            ($query['response_type'] ?? null) !== 'code' => 'response_type is not "code"',
            ($query['client_id'] ?? null) !== self::CLIENT_ID => 'the client_id is not '.self::CLIENT_ID,
            ! is_string($query['redirect_uri'] ?? null) => 'it has no redirect_uri',
            ! is_string($query['state'] ?? null) || strlen($query['state']) < 32 => 'it has no state',
            ($query['code_challenge_method'] ?? null) !== 'S256' || ! is_string($query['code_challenge'] ?? null) => 'it has no S256 code challenge',
            $this->driver !== 'github' && ! is_string($query['nonce'] ?? null) => 'it has no nonce',
            isset($query['response_mode']) && $query['response_mode'] !== 'query' => 'it asks for another response_mode',
            isset($query['max_age']) && (! is_string($query['max_age']) || ! ctype_digit($query['max_age'])) => 'its max_age is not a number of seconds',
            $this->driver === 'google' && ($query['prompt'] ?? null) === 'login' => 'Google takes no prompt=login',
            default => null,
        };

        if ($problem !== null) {
            throw new InvalidArgumentException("The authorization request is refused: {$problem}.");
        }

        /** @var array<string, mixed> $query */
        return $query;
    }

    /**
     * @param  array<string, mixed>  $request
     * @param  array<string, string>  $answer
     */
    protected function callback(array $request, array $answer): string
    {
        $answer['state'] = $request['state'];

        if ($this->sendsIssuer) {
            $answer['iss'] = $this->tokenIssuer();
        }

        return $request['redirect_uri'].(str_contains($request['redirect_uri'], '?') ? '&' : '?').http_build_query($answer, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @return array{authorization_endpoint: string, token_endpoint: string, jwks_uri: string}
     */
    protected function endpoints(): array
    {
        if ($this->driver === 'github') {
            return [
                'authorization_endpoint' => 'https://github.com/login/oauth/authorize',
                'token_endpoint' => 'https://github.com/login/oauth/access_token',
                'jwks_uri' => '',
            ];
        }

        $base = rtrim($this->issuer, '/');

        return [
            'authorization_endpoint' => $base.'/authorize',
            'token_endpoint' => $base.'/token',
            'jwks_uri' => $base.'/keys',
        ];
    }

    /**
     * What it answers a request with, or null for a request that isn't to it.
     */
    protected function answer(Request $request): mixed
    {
        $url = Str::before($request->url(), '?');
        $endpoints = $this->endpoints();

        return match (true) {
            $url === $endpoints['token_endpoint'] => $this->token($request),
            $this->driver === 'github' && str_starts_with($url, GitHubProvider::API.'/') => $this->api($request, Str::after($url, GitHubProvider::API)),
            $this->driver !== 'github' && $url === rtrim($this->issuer, '/').'/.well-known/openid-configuration' => $this->discover(),
            $this->driver !== 'github' && $url === $endpoints['jwks_uri'] => $this->keySet(),
            default => null,
        };
    }

    protected function discover(): mixed
    {
        $this->discoveryFetches++;

        if ($this->down) {
            return Http::response(null, 503);
        }

        $issuer = match (true) {
            $this->driver !== 'microsoft' => $this->issuer,
            str_contains($this->issuer, '/common/') || str_contains($this->issuer, '/organizations/') => MicrosoftProvider::AUTHORITY.'/{tenantid}/v2.0',
            default => $this->tokenIssuer(),
        };

        return Http::response(array_filter([
            'issuer' => $issuer,
            ...$this->endpoints(),
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => [$this->algorithm],
            'token_endpoint_auth_methods_supported' => $this->authMethods,
            'code_challenge_methods_supported' => ['S256'],
            'authorization_response_iss_parameter_supported' => $this->sendsIssuer ?: null,
            ...$this->discovery,
        ], fn (mixed $value) => $value !== null));
    }

    protected function keySet(): mixed
    {
        $this->keyFetches++;

        return $this->down ? Http::response(null, 503) : Http::response(['keys' => $this->jwks()]);
    }

    /**
     * The token endpoint. GitHub answers a refused code with a 200 and the
     * error in the body, as the real one does.
     */
    protected function token(Request $request): mixed
    {
        $refuse = fn (string $error, int $status = 400) => Http::response(['error' => $error], $this->driver === 'github' ? 200 : $status);

        if ($this->exchangeFailure !== null) {
            return $refuse($this->exchangeFailure[1], $this->exchangeFailure[0]);
        }

        $data = $request->data();
        $grant = $this->codes[$data['code'] ?? ''] ?? null;
        unset($this->codes[$data['code'] ?? '']);

        $problem = match (true) {
            $grant === null || ($data['grant_type'] ?? null) !== 'authorization_code' => 'invalid_grant',
            ($data['redirect_uri'] ?? null) !== $grant['redirect_uri'] => 'invalid_grant',
            ! is_string($data['code_verifier'] ?? null) || Base64UrlSafe::encodeUnpadded(hash('sha256', $data['code_verifier'], true)) !== $grant['challenge'] => 'invalid_grant',
            ! $this->authenticates($request, $grant['client_id']) => 'invalid_client',
            default => null,
        };

        if ($problem !== null) {
            return $refuse($problem, $problem === 'invalid_client' ? 401 : 400);
        }

        $this->accessTokens[] = $accessToken = 'fake-access-'.Str::random(32);

        if ($this->driver === 'github') {
            return Http::response(['access_token' => $accessToken, 'token_type' => 'bearer', 'scope' => str_replace(' ', ',', $grant['scope'])]);
        }

        $now = now()->getTimestamp();

        return Http::response([
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'id_token' => $this->idToken([
                'iss' => $this->tokenIssuer(),
                'aud' => $grant['client_id'],
                'iat' => $now,
                'exp' => $now + 3600,
                'nonce' => $grant['nonce'],
                'auth_time' => $grant['auth_time'],
                ...($this->driver === 'microsoft' ? ['tid' => $this->tenantId] : []),
                ...$this->user,
            ]),
        ]);
    }

    /**
     * Whether the client proved who it is in a way the endpoint takes. A
     * client sending no secret at all is a public one.
     */
    protected function authenticates(Request $request, string $clientId): bool
    {
        $data = $request->data();

        if ($request->hasHeader('Authorization')) {
            [$id, $secret] = array_map(urldecode(...), explode(':', base64_decode(Str::after($request->header('Authorization')[0], 'Basic ')), 2) + [1 => '']);

            return in_array('client_secret_basic', $this->authMethods, true) && $id === $clientId && $secret === self::CLIENT_SECRET;
        }

        if (isset($data['client_secret'])) {
            return in_array('client_secret_post', $this->authMethods, true) && ($data['client_id'] ?? null) === $clientId && $data['client_secret'] === self::CLIENT_SECRET;
        }

        return ($data['client_id'] ?? null) === $clientId;
    }

    /**
     * GitHub's user API, for an access token it handed out.
     */
    protected function api(Request $request, string $path): mixed
    {
        if ($this->down) {
            return Http::response(null, 503);
        }

        if (! in_array(Str::after($request->header('Authorization')[0] ?? '', 'Bearer '), $this->accessTokens, true)) {
            return Http::response(['message' => 'Bad credentials'], 401);
        }

        return Http::response($path === '/user/emails' ? $this->emails : $this->user);
    }

    /**
     * @param  array<string, mixed>  $value
     */
    protected function encode(array $value): string
    {
        return Base64UrlSafe::encodeUnpadded(json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
    }

    /**
     * @return OpenSSLAsymmetricKey|non-empty-string
     */
    protected function makeKey(): OpenSSLAsymmetricKey|string
    {
        return match ($this->algorithm) {
            'EdDSA' => sodium_crypto_sign_keypair(),
            'RS256', 'PS256' => openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA])
                ?: throw new RuntimeException('OpenSSL could not make an RSA key pair.'),
            default => openssl_pkey_new(['curve_name' => 'prime256v1', 'private_key_type' => OPENSSL_KEYTYPE_EC])
                ?: throw new RuntimeException('OpenSSL could not make a P-256 key pair.'),
        };
    }

    /**
     * @param  OpenSSLAsymmetricKey|non-empty-string  $key
     */
    protected function sign(string $data, OpenSSLAsymmetricKey|string $key): string
    {
        if (is_string($key)) {
            return sodium_crypto_sign_detached($data, sodium_crypto_sign_secretkey($key));
        }

        openssl_sign($data, $signature, $key, OPENSSL_ALGO_SHA256, $this->algorithm === 'PS256' ? OPENSSL_PKCS1_PSS_PADDING : 0);

        return $this->algorithm === 'ES256' ? $this->rawSignature($signature) : $signature;
    }

    /**
     * OpenSSL's DER signature as JWS wants it: r and s, 32 bytes each.
     */
    protected function rawSignature(string $der): string
    {
        $offset = 2;
        $raw = '';

        foreach ([0, 1] as $ignored) {
            $length = ord($der[$offset + 1]);
            $raw .= str_pad(ltrim(substr($der, $offset + 2, $length), "\0"), 32, "\0", STR_PAD_LEFT);
            $offset += 2 + $length;
        }

        return $raw;
    }

    /**
     * @param  OpenSSLAsymmetricKey|non-empty-string  $key
     * @return array<string, string>
     */
    protected function jwk(string $kid, OpenSSLAsymmetricKey|string $key): array
    {
        $encode = Base64UrlSafe::encodeUnpadded(...);
        $base = ['kid' => $kid, 'use' => 'sig', 'alg' => $this->algorithm, ...($this->keyIssuer === null ? [] : ['issuer' => $this->keyIssuer])];

        if (is_string($key)) {
            return [...$base, 'kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $encode(sodium_crypto_sign_publickey($key))];
        }

        $details = openssl_pkey_get_details($key) ?: throw new RuntimeException('OpenSSL could not read the key pair.');

        if (isset($details['rsa'])) {
            return [...$base, 'kty' => 'RSA', 'n' => $encode($details['rsa']['n']), 'e' => $encode($details['rsa']['e'])];
        }

        return [
            ...$base,
            'kty' => 'EC',
            'crv' => 'P-256',
            'x' => $encode(str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT)),
            'y' => $encode(str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT)),
        ];
    }

    /**
     * The public key in PEM, as a verifier that confuses algorithms would
     * take for an HMAC secret.
     *
     * @param  OpenSSLAsymmetricKey|non-empty-string  $key
     */
    protected function pem(OpenSSLAsymmetricKey|string $key): string
    {
        return is_string($key) ? sodium_crypto_sign_publickey($key) : (openssl_pkey_get_details($key) ?: throw new RuntimeException('OpenSSL could not read the key pair.'))['key'];
    }
}
