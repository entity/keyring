<?php

declare(strict_types=1);

namespace Keyring\Sso\Providers;

use InvalidArgumentException;
use Keyring\Enums\SsoFailure;
use Keyring\Enums\SsoFreshness;
use Keyring\Exceptions\SsoFailed;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\Metadata;
use Keyring\Sso\SignedToken;

/**
 * Any OpenID Connect provider, found from its issuer through discovery
 * (OpenID Connect Discovery 1.0). Who signed in comes from the ID token,
 * which is only believed once every check OpenID Connect Core 1.0 asks for
 * (Sec. 3.1.3.7) has passed: it's signed by one of the provider's published
 * keys with an asymmetric algorithm, it's from the configured issuer, for
 * this app, current, and carries the nonce this sign in was started with.
 *
 * The token came straight from the provider's token endpoint over TLS, so
 * strictly its signature needn't be checked. It is anyway, so a token
 * endpoint that's misconfigured, or a TLS proxy in between, can't hand over
 * someone else.
 */
class OidcProvider extends OAuth2Provider
{
    /**
     * Seconds the provider's clock and this server's may disagree by.
     */
    public const int LEEWAY = 60;

    /**
     * What a discovery document has to name for a sign in to work.
     */
    protected const array REQUIRED_ENDPOINTS = ['authorization_endpoint', 'token_endpoint', 'jwks_uri'];

    /**
     * Read once for each provider built, which is once per request.
     *
     * @var array<string, mixed>|null
     */
    protected ?array $discovery = null;

    /**
     * @param  array<string, mixed>  $config
     */
    public function __construct(string $name, array $config)
    {
        parent::__construct($name, $config);

        if (! Metadata::isSecure($this->issuer())) {
            throw new InvalidArgumentException("Identity provider [{$name}] needs an HTTPS issuer.");
        }
    }

    /**
     * The issuer as configured, which is where its discovery document is.
     */
    public function issuer(): string
    {
        $issuer = $this->config['issuer'] ?? null;

        return is_string($issuer) ? $issuer : '';
    }

    protected function discoveryUrl(): string
    {
        return rtrim($this->issuer(), '/').'/.well-known/openid-configuration';
    }

    /**
     * The provider's discovery document, checked before it's cached.
     *
     * @return array<string, mixed>
     *
     * @throws SsoFailed
     */
    protected function discovery(): array
    {
        return $this->discovery ??= app(Metadata::class)->discover($this->discoveryUrl(), $this->checkDiscovery(...));
    }

    /**
     * Refuse a discovery document that isn't the issuer's own: one that
     * names another issuer (Discovery, Sec. 4.3), or lacks an endpoint a
     * sign in needs.
     *
     * @param  array<string, mixed>  $document
     *
     * @throws SsoFailed
     */
    protected function checkDiscovery(array $document): void
    {
        if (! is_string($document['issuer'] ?? null) || ! $this->trustsDiscoveredIssuer($document['issuer'])) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s discovery document is for another issuer.");
        }

        foreach (static::REQUIRED_ENDPOINTS as $key) {
            $this->endpointIn($document, $key);
        }
    }

    protected function trustsDiscoveredIssuer(string $issuer): bool
    {
        return $issuer === $this->issuer();
    }

    /**
     * The issuer tokens come from, as discovery gave it.
     *
     * @throws SsoFailed
     */
    protected function discoveredIssuer(): string
    {
        return $this->discovery()['issuer'];
    }

    /**
     * @throws SsoFailed
     */
    protected function endpoint(string $key): string
    {
        return $this->endpointIn($this->discovery(), $key);
    }

    /**
     * An endpoint the document names, which has to be HTTPS. Only an issuer
     * on this machine may name endpoints on it, or plain HTTP ones there:
     * a provider elsewhere can't have Keyring send requests to the
     * server's own services.
     *
     * @param  array<string, mixed>  $document
     *
     * @throws SsoFailed
     */
    protected function endpointIn(array $document, string $key): string
    {
        $url = $document[$key] ?? null;

        if (! is_string($url) || ! Metadata::isSecure($url, local: Metadata::isLocal($this->issuer()))) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$this->name}]'s discovery document has no HTTPS {$key}.");
        }

        return $url;
    }

    protected function authorizationEndpoint(): string
    {
        return $this->endpoint('authorization_endpoint');
    }

    protected function tokenEndpoint(): string
    {
        return $this->endpoint('token_endpoint');
    }

    protected function defaultScopes(): array
    {
        return ['openid', 'email', 'profile'];
    }

    /**
     * The scopes asked for, which always include openid: without it the
     * provider sends no ID token.
     */
    protected function scopes(): array
    {
        return array_values(array_unique(['openid', ...parent::scopes()]));
    }

    /**
     * OpenID Connect has auth_time, max_age and prompt=login, so any
     * provider can be asked, though it's up to its freshness() whether it
     * is.
     */
    public function supportsReauthentication(): bool
    {
        return true;
    }

    /**
     * OpenID Connect Core 1.0 has a provider send auth_time whenever
     * max_age asks for it (Sec. 3.1.2.1), so any provider is taken to.
     */
    protected function defaultFreshness(): SsoFreshness
    {
        return SsoFreshness::Reauthenticate;
    }

    /**
     * login_hint when the request names the account, auth_time asked for
     * as an essential claim where the provider takes the claims parameter,
     * with every sign in when its freshness() is SsoFreshness::Reauthenticate
     * and otherwise with a request that has a maxAge, and for one with a
     * maxAge, what asks for a sign in that recent.
     */
    protected function authorizationParameters(AuthorizationRequest $request): array
    {
        $asksAuthTime = $request->maxAge !== null || $this->freshness() === SsoFreshness::Reauthenticate;

        return [
            ...parent::authorizationParameters($request),
            'nonce' => $request->nonce,
            ...($request->loginHint === null ? [] : ['login_hint' => $request->loginHint]),
            ...($asksAuthTime && $this->takesClaimsParameter() ? ['claims' => $this->claimsParameter()] : []),
            ...($request->maxAge === null ? [] : $this->reauthenticationParameters($request->maxAge)),
        ];
    }

    /**
     * Whether auth_time can be asked for with the claims parameter (Core,
     * Sec. 5.5): when the provider's discovery says it takes one. Without
     * it, a provider only has to send auth_time for max_age.
     *
     * @throws SsoFailed
     */
    protected function takesClaimsParameter(): bool
    {
        return ($this->discovery()['claims_parameter_supported'] ?? false) === true;
    }

    /**
     * The claims parameter: any the config's "parameters" ask for, with
     * auth_time in the ID token as an essential claim.
     */
    protected function claimsParameter(): string
    {
        $configured = $this->parameters()['claims'] ?? null;
        $claims = is_string($configured) ? json_decode($configured, true) : null;
        $claims = is_array($claims) ? $claims : [];
        $idToken = is_array($claims['id_token'] ?? null) ? $claims['id_token'] : [];

        return (string) json_encode([...$claims, 'id_token' => [...$idToken, 'auth_time' => ['essential' => true]]], JSON_UNESCAPED_SLASHES);
    }

    /**
     * What asks for a sign in no older than $maxAge seconds: max_age, and
     * for 0, prompt=login as well, in place of any prompt in the config.
     *
     * @return array<string, string>
     */
    protected function reauthenticationParameters(int $maxAge): array
    {
        return ['max_age' => (string) $maxAge, ...($maxAge === 0 ? ['prompt' => 'login'] : [])];
    }

    /**
     * client_secret_basic, the default OpenID Connect assumes, unless the
     * config names one, or the provider's discovery lists only
     * client_secret_post.
     */
    protected function authMethod(): string
    {
        if (isset($this->config['token_endpoint_auth_method'])) {
            return parent::authMethod();
        }

        $supported = $this->discovery()['token_endpoint_auth_methods_supported'] ?? null;

        return is_array($supported) && ! in_array('client_secret_basic', $supported, true) && in_array('client_secret_post', $supported, true)
            ? 'client_secret_post'
            : 'client_secret_basic';
    }

    /**
     * The callback has to come from this provider. One that says it's from
     * another issuer (RFC 9207's "iss") was sent there, and its code
     * belongs to that issuer: it isn't sent to this one's token endpoint.
     * A provider whose discovery says it always sends "iss" mustn't leave
     * it out.
     */
    protected function checkCallback(array $query): void
    {
        $issuer = $query['iss'] ?? null;

        if ($issuer === null && ($this->discovery()['authorization_response_iss_parameter_supported'] ?? false) === true) {
            throw SsoFailed::because(SsoFailure::InvalidResponse, "The callback from [{$this->name}] has no iss, which its discovery says it sends.");
        }

        if ($issuer !== null && (! is_string($issuer) || ! $this->acceptsIssuerParameter($issuer))) {
            throw SsoFailed::because(SsoFailure::InvalidResponse, "The callback for [{$this->name}] came from another issuer.");
        }

        parent::checkCallback($query);
    }

    /**
     * @throws SsoFailed
     */
    protected function acceptsIssuerParameter(string $issuer): bool
    {
        return $issuer === $this->discoveredIssuer();
    }

    protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity
    {
        if (! is_string($tokens['id_token'] ?? null)) {
            throw SsoFailed::because(SsoFailure::InvalidToken, "[{$this->name}]'s token endpoint sent no ID token.");
        }

        $claims = $this->verify($tokens['id_token'], $request);
        $issuer = $claims['iss'];

        // Where the issuer is only known from the token (Microsoft's
        // multi-tenant endpoints), the callback's has to match it too.
        if (isset($query['iss']) && $query['iss'] !== $issuer) {
            throw SsoFailed::because(SsoFailure::InvalidResponse, "The callback for [{$this->name}] came from another issuer.");
        }

        return new Identity(
            request: $request,
            provider: $this->name,
            issuer: $issuer,
            subject: $claims['sub'],
            email: is_string($claims['email'] ?? null) ? $claims['email'] : null,
            emailVerified: is_string($claims['email'] ?? null) && $this->emailVerified($claims),
            name: is_string($claims['name'] ?? null) ? $claims['name'] : null,
            authTime: static::time($claims['auth_time'] ?? null),
            amr: is_array($claims['amr'] ?? null) ? array_values(array_filter($claims['amr'], is_string(...))) : [],
            acr: is_string($claims['acr'] ?? null) ? $claims['acr'] : null,
            claims: $claims,
        );
    }

    /**
     * Whether the provider vouches for the address: email_verified is true,
     * the boolean and not a string of it.
     *
     * @param  array<string, mixed>  $claims
     */
    protected function emailVerified(array $claims): bool
    {
        return ($claims['email_verified'] ?? null) === true;
    }

    /**
     * The ID token's claims, once it has passed every check. Its "iss" is
     * then the issuer as it should be named, and its "sub" a string.
     *
     * @return array<string, mixed>
     *
     * @throws SsoFailed
     */
    protected function verify(string $idToken, AuthorizationRequest $request): array
    {
        try {
            $token = SignedToken::parse($idToken);
        } catch (InvalidArgumentException $e) {
            $this->refuse('The ID token is unreadable: '.$e->getMessage());
        }

        if (! in_array($token->algorithm(), SignedToken::ALGORITHMS, true)) {
            $this->refuse("The ID token is signed with [{$this->printable($token->algorithm())}], which isn't allowed.");
        }

        if (! $this->signedByProvider($token)) {
            $this->refuse('The ID token is not signed by any of the provider\'s keys.');
        }

        $claims = $token->claims;
        $now = now()->getTimestamp();

        $issuer = $this->acceptedIssuer($claims) ?? $this->refuse('The ID token is from another issuer.');

        $audience = is_string($claims['aud'] ?? null) ? [$claims['aud']] : ($claims['aud'] ?? null);

        if (! is_array($audience) || ! in_array($this->clientId(), $audience, true)) {
            $this->refuse('The ID token is for another app.');
        }

        // The party it was issued to, which has to be this app when it's
        // named, and has to be named when the token is for others too.
        if (array_key_exists('azp', $claims) ? $claims['azp'] !== $this->clientId() : count($audience) > 1) {
            $this->refuse('The ID token was issued to another app.');
        }

        $expires = static::time($claims['exp'] ?? null);
        $issued = static::time($claims['iat'] ?? null);
        $notBefore = static::time($claims['nbf'] ?? null);

        if ($expires === null || $expires + static::LEEWAY <= $now) {
            $this->refuse('The ID token has expired.');
        }

        if ($issued === null || $issued - static::LEEWAY > $now) {
            $this->refuse('The ID token has no time of issue, or one in the future.');
        }

        if (array_key_exists('nbf', $claims) && ($notBefore === null || $notBefore - static::LEEWAY > $now)) {
            $this->refuse('The ID token is not valid yet.');
        }

        if (! is_string($claims['nonce'] ?? null) || ! hash_equals($request->nonce, $claims['nonce'])) {
            $this->refuse('The ID token was issued for another sign in.');
        }

        if (! is_string($claims['sub'] ?? null) || $claims['sub'] === '' || strlen($claims['sub']) > 255) {
            $this->refuse('The ID token names no subject.');
        }

        return [...$claims, 'iss' => $issuer];
    }

    /**
     * The issuer named the way Keyring keeps it, when the token's "iss" is
     * one this provider issues as, or null.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws SsoFailed
     */
    protected function acceptedIssuer(array $claims): ?string
    {
        return ($claims['iss'] ?? null) === $this->discoveredIssuer() ? $this->discoveredIssuer() : null;
    }

    /**
     * Whether one of the provider's keys signed the token. A key ID that
     * isn't among them may be a key the provider has only just started
     * signing with, so the keys are read again, as often as
     * Metadata::REFETCH_EVERY allows.
     *
     * @throws SsoFailed
     */
    protected function signedByProvider(SignedToken $token): bool
    {
        $metadata = app(Metadata::class);
        $url = $this->endpoint('jwks_uri');
        $keys = $metadata->keys($url);

        if ($this->signedByOneOf($token, $keys)) {
            return true;
        }

        $kid = $token->keyId();

        if ($kid === null || in_array($kid, array_column($keys, 'kid'), true)) {
            return false;
        }

        $keys = $metadata->refreshKeys($url);

        return $keys !== null && $this->signedByOneOf($token, $keys);
    }

    /**
     * @param  list<array<array-key, mixed>>  $keys
     */
    protected function signedByOneOf(SignedToken $token, array $keys): bool
    {
        $kid = $token->keyId();

        return array_any($keys, fn (array $key) => ($kid === null || ($key['kid'] ?? null) === $kid) && $token->signedBy($key));
    }

    /**
     * A NumericDate (RFC 7519): seconds since the epoch, which may have a
     * fraction. One too large for an integer is no date.
     */
    protected static function time(mixed $value): ?int
    {
        return match (true) {
            is_int($value) => $value,
            is_float($value) && abs($value) < 1e15 => (int) floor($value),
            default => null,
        };
    }

    /**
     * @throws SsoFailed
     */
    protected function refuse(string $why): never
    {
        throw SsoFailed::because(SsoFailure::InvalidToken, "[{$this->name}]: {$why}");
    }
}
