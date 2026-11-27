<?php

declare(strict_types=1);

namespace Keyring\Sso;

use Keyring\Support\Duration;
use ParagonIE\ConstantTime\Base64UrlSafe;

/**
 * A user sent to an identity provider and not back yet. It's kept in the
 * session under its state until the callback, which can use it once.
 *
 * The state ties the callback to this browser's session, so another site
 * can't finish a sign in it started for someone else. The nonce ties the ID
 * token to this request, so one handed out for another sign in can't be
 * replayed into it. The code verifier is PKCE's (RFC 7636): only whoever
 * started the request can exchange its code, so a code that leaks from the
 * callback URL is worth nothing on its own.
 *
 * The purpose says what the sign in is for ("login", "link"...), and data
 * is anything else the app wants back with the callback. Both stay on the
 * server, never in the URL.
 *
 * maxAge asks for a user who signed in at the provider at most that many
 * seconds before, as OpenID Connect's max_age does. 0 asks them to sign in
 * again there and then, whatever session they have. Null asks nothing,
 * and a session of any age will do. It's measured from createdAt, when the
 * user was sent there, as the provider measures it: however long they then
 * take over its sign in, consent or second factor.
 *
 * loginHint says which account the user should sign in with there, as
 * OpenID Connect's login_hint does, for a provider that takes one.
 */
final class AuthorizationRequest
{
    public bool $expired {
        get => $this->expiresAt < now()->getTimestamp();
    }

    /**
     * @param  array<string, mixed>  $data
     */
    public function __construct(
        public readonly string $provider,
        public readonly string $purpose,
        public readonly string $redirectUri,
        public readonly string $state,
        public readonly string $nonce,
        public readonly string $codeVerifier,
        public readonly int $expiresAt,
        public readonly int $createdAt,
        public readonly array $data = [],
        public readonly ?int $maxAge = null,
        public readonly ?string $loginHint = null,
    ) {}

    /**
     * A new request, valid for keyring.sso.request_for. Each secret is 32
     * random bytes, base64url encoded: 43 characters, the shortest code
     * verifier RFC 7636 allows.
     *
     * @param  array<string, mixed>  $data
     */
    public static function make(string $provider, string $purpose, string $redirectUri, array $data = [], ?int $maxAge = null, ?string $loginHint = null): self
    {
        return new self(
            $provider,
            $purpose,
            $redirectUri,
            self::secret(),
            self::secret(),
            self::secret(),
            Duration::fromNow(config('keyring.sso.request_for'))->getTimestamp(),
            now()->getTimestamp(),
            $data,
            $maxAge,
            $loginHint,
        );
    }

    /**
     * The S256 challenge sent with the user, for the verifier sent with the
     * code.
     */
    public function codeChallenge(): string
    {
        return Base64UrlSafe::encodeUnpadded(hash('sha256', $this->codeVerifier, true));
    }

    /**
     * The request without its state, nonce or code verifier, each blank:
     * what's left of one that's spent, for an event that's queued. It can
     * never finish a sign in.
     */
    public function withoutSecrets(): self
    {
        return new self($this->provider, $this->purpose, $this->redirectUri, '', '', '', $this->expiresAt, $this->createdAt, $this->data, $this->maxAge, $this->loginHint);
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'provider' => $this->provider,
            'purpose' => $this->purpose,
            'redirect_uri' => $this->redirectUri,
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'expires_at' => $this->expiresAt,
            'data' => $this->data,
            'max_age' => $this->maxAge,
            'created_at' => $this->createdAt,
            'login_hint' => $this->loginHint,
        ];
    }

    /**
     * Throws a TypeError for anything that isn't what toArray() gave.
     *
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            $data['provider'] ?? null,
            $data['purpose'] ?? null,
            $data['redirect_uri'] ?? null,
            $data['state'] ?? null,
            $data['nonce'] ?? null,
            $data['code_verifier'] ?? null,
            $data['expires_at'] ?? null,
            $data['created_at'] ?? null,
            $data['data'] ?? null,
            $data['max_age'] ?? null,
            $data['login_hint'] ?? null,
        );
    }

    private static function secret(): string
    {
        return Base64UrlSafe::encodeUnpadded(random_bytes(32));
    }
}
