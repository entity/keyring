<?php

declare(strict_types=1);

namespace Keyring\Sso\Providers;

use Illuminate\Http\Client\Response;
use Illuminate\Http\Request;
use InvalidArgumentException;
use Keyring\Contracts\IdentityProvider;
use Keyring\Enums\SsoFailure;
use Keyring\Enums\SsoFreshness;
use Keyring\Exceptions\SsoFailed;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;
use Keyring\Sso\Metadata;
use Throwable;

/**
 * The OAuth 2.0 authorization code flow (RFC 6749) that every provider here
 * signs in with: the user is sent to the provider, comes back with a code,
 * and the code is exchanged for tokens, which a subclass turns into who
 * they are.
 *
 * Every request carries a PKCE challenge (RFC 7636, S256), as OAuth 2.1 and
 * RFC 9700 ask of every client, secret or not. The callback is only read
 * from the query string. A provider posting it back (response_mode
 * form_post) would come from another site, a cross-site POST the session
 * cookie isn't sent with under SameSite=Lax, and the state could then
 * never be found.
 */
abstract class OAuth2Provider implements IdentityProvider
{
    /**
     * What Keyring sends itself, which "parameters" in the config can't
     * replace. max_age is here because asking for it means checking
     * auth_time against it, which Keyring does when it asks for it itself
     * (AuthorizationRequest::$maxAge).
     */
    protected const array RESERVED = [
        'response_type', 'response_mode', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce',
        'code_challenge', 'code_challenge_method', 'max_age', 'request', 'request_uri',
    ];

    /**
     * @param  array<string, mixed>  $config  the provider's entry in keyring.sso.providers
     */
    public function __construct(
        protected string $name,
        protected array $config,
    ) {
        if (! is_string($config['client_id'] ?? null) || $config['client_id'] === '') {
            throw new InvalidArgumentException("Identity provider [{$name}] needs a client_id.");
        }

        foreach (array_keys($this->parameters()) as $parameter) {
            if (in_array($parameter, static::RESERVED, true)) {
                throw new InvalidArgumentException("Identity provider [{$name}] can't set the [{$parameter}] parameter: Keyring sends it.");
            }
        }
    }

    abstract protected function authorizationEndpoint(): string;

    abstract protected function tokenEndpoint(): string;

    /**
     * @return list<string>
     */
    abstract protected function defaultScopes(): array;

    /**
     * Who signed in, from what the token endpoint sent back.
     *
     * @param  array<string, mixed>  $tokens
     * @param  array<array-key, mixed>  $query  the callback's query string
     *
     * @throws SsoFailed
     */
    abstract protected function identityFrom(AuthorizationRequest $request, array $tokens, array $query): Identity;

    public function name(): string
    {
        return $this->name;
    }

    public function label(): string
    {
        return is_string($this->config['name'] ?? null) ? $this->config['name'] : $this->defaultLabel();
    }

    /**
     * Plain OAuth 2.0 has no way to ask for a new sign in, nor to say when
     * there was one.
     */
    public function supportsReauthentication(): bool
    {
        return false;
    }

    /**
     * "freshness" in its config, or defaultFreshness() without one.
     *
     * @throws InvalidArgumentException for a value that isn't one
     */
    public function freshness(): SsoFreshness
    {
        return SsoFreshness::configured($this->config['freshness'] ?? null, $this->name, $this->defaultFreshness());
    }

    /**
     * What a sign in through it counts for unless the config says: never,
     * since nothing Keyring trusts says when the user signed in there, and
     * a round trip there may let them straight through on an old session.
     */
    protected function defaultFreshness(): SsoFreshness
    {
        return SsoFreshness::Never;
    }

    public function authorizationUrl(AuthorizationRequest $request): string
    {
        $endpoint = $this->authorizationEndpoint();

        return $endpoint.(str_contains($endpoint, '?') ? '&' : '?')
            .http_build_query([...$this->parameters(), ...$this->authorizationParameters($request)], '', '&', PHP_QUERY_RFC3986);
    }

    public function identify(AuthorizationRequest $request, Request $callback): Identity
    {
        $query = $callback->query->all();

        $this->checkCallback($query);

        $code = $query['code'] ?? null;

        if (! is_string($code) || $code === '') {
            throw SsoFailed::because(SsoFailure::InvalidResponse, "The callback from [{$this->name}] has no code.");
        }

        return $this->identityFrom($request, $this->exchange($request, $code), $query);
    }

    protected function defaultLabel(): string
    {
        return str($this->name)->headline()->toString();
    }

    /**
     * @return list<string>
     */
    protected function scopes(): array
    {
        $scopes = $this->config['scopes'] ?? null;

        return is_array($scopes) ? array_values(array_filter($scopes, is_string(...))) : $this->defaultScopes();
    }

    /**
     * Anything more to send the user with, from the config: a "prompt" or
     * a "login_hint", say.
     *
     * @return array<string, mixed>
     */
    protected function parameters(): array
    {
        $parameters = $this->config['parameters'] ?? [];

        return is_array($parameters) ? $parameters : [];
    }

    /**
     * @return array<string, string>
     */
    protected function authorizationParameters(AuthorizationRequest $request): array
    {
        return [
            'response_type' => 'code',
            'client_id' => $this->clientId(),
            'redirect_uri' => $request->redirectUri,
            'scope' => implode(' ', $this->scopes()),
            'state' => $request->state,
            'code_challenge' => $request->codeChallenge(),
            'code_challenge_method' => 'S256',
        ];
    }

    /**
     * Refuse a callback that says the provider didn't sign anyone in.
     *
     * @param  array<array-key, mixed>  $query
     *
     * @throws SsoFailed
     */
    protected function checkCallback(array $query): void
    {
        if (! array_key_exists('error', $query)) {
            return;
        }

        if ($query['error'] === 'access_denied') {
            throw SsoFailed::because(SsoFailure::Denied, "The user declined to sign in with [{$this->name}].");
        }

        throw SsoFailed::because(SsoFailure::ProviderError, "[{$this->name}] answered with the error [{$this->printable($query['error'])}].");
    }

    /**
     * Swap the code for tokens, proving with the code verifier that this is
     * who asked for it. A client with a secret proves that too, in the way
     * authMethod() picks. One without (a public client) sends only its ID.
     *
     * @return array<string, mixed>
     *
     * @throws SsoFailed
     */
    protected function exchange(AuthorizationRequest $request, string $code): array
    {
        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $request->redirectUri,
            'code_verifier' => $request->codeVerifier,
        ];

        $http = Metadata::http()->asForm();
        $secret = $this->config['client_secret'] ?? null;

        if (! is_string($secret) || $secret === '') {
            $form['client_id'] = $this->clientId();
        } elseif ($this->authMethod() === 'client_secret_post') {
            $form['client_id'] = $this->clientId();
            $form['client_secret'] = $secret;
        } else {
            // Each half is form-encoded first (RFC 6749, Sec. 2.3.1), so a
            // colon in the ID can't move where the secret starts.
            $http = $http->withHeaders(['Authorization' => 'Basic '.base64_encode(urlencode($this->clientId()).':'.urlencode($secret))]);
        }

        $endpoint = $this->tokenEndpoint();

        try {
            $response = $http->post($endpoint, $form);
        } catch (Throwable) {
            throw SsoFailed::because(SsoFailure::ExchangeFailed, "[{$this->name}]'s token endpoint could not be reached.");
        }

        return $this->tokens($response);
    }

    /**
     * What the token endpoint sent back, when it's tokens. Some providers
     * (GitHub) answer a refused code with a 200 and an error in the body.
     *
     * @return array<string, mixed>
     *
     * @throws SsoFailed
     */
    protected function tokens(Response $response): array
    {
        $tokens = rescue(fn () => $response->json(), report: false);

        if (! is_array($tokens) || isset($tokens['error']) || $response->failed()) {
            $error = is_array($tokens) && isset($tokens['error']) ? ' with the error ['.$this->printable($tokens['error']).']' : '';

            throw SsoFailed::because(SsoFailure::ExchangeFailed, "[{$this->name}]'s token endpoint refused the code ({$response->status()}){$error}.");
        }

        if (! is_string($tokens['access_token'] ?? null)) {
            throw SsoFailed::because(SsoFailure::ExchangeFailed, "[{$this->name}]'s token endpoint sent no access token.");
        }

        return $tokens;
    }

    /**
     * client_secret_basic, unless the config says client_secret_post.
     */
    protected function authMethod(): string
    {
        return ($this->config['token_endpoint_auth_method'] ?? null) === 'client_secret_post' ? 'client_secret_post' : 'client_secret_basic';
    }

    protected function clientId(): string
    {
        return $this->config['client_id'];
    }

    /**
     * An error code from the provider, as far as it's safe to put in a
     * message that gets logged. Error codes are short ASCII words (RFC
     * 6749, Sec. 4.1.2.1): anything else was made up by whoever sent the
     * callback.
     */
    protected function printable(mixed $value): string
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $value) === 1 ? $value : 'unreadable';
    }
}
