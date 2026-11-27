<?php

declare(strict_types=1);

namespace Keyring\Contracts;

use Illuminate\Http\Request;
use Keyring\Enums\SsoFreshness;
use Keyring\Exceptions\SsoFailed;
use Keyring\Sso\AuthorizationRequest;
use Keyring\Sso\Identity;

/**
 * Somewhere users can sign in instead: an OpenID Connect provider, or an
 * OAuth 2.0 API that says who its user is. Keyring makes the request, keeps
 * it in the session and takes it back from the callback. The provider only
 * turns it into a URL to send the user to, and the callback into who signed
 * in.
 *
 * Register one of your own with Keyring::sso()->extend().
 */
interface IdentityProvider
{
    /**
     * Its name in keyring.sso.providers, as routes and the session know it.
     */
    public function name(): string;

    /**
     * What it's called on a "Sign in with ..." button.
     */
    public function label(): string;

    /**
     * Whether it can say when the user signed in there, and be asked to
     * have them sign in again there and then: OpenID Connect's auth_time,
     * prompt=login and max_age. One that can't (GitHub, any plain OAuth 2.0
     * API) can't have a freshness() of SsoFreshness::Reauthenticate, nor be
     * started with a maxAge.
     */
    public function supportsReauthentication(): bool;

    /**
     * How much a sign in or a confirm through it counts toward a fresh
     * verification by default. A "freshness" in its config wins over this:
     * Keyring::sso()->freshness() says what counts, so a driver needn't
     * read the config itself. SsoFreshness::Reauthenticate counts a sign in
     * from its auth_time and has a confirm sign in again, RoundTrip counts
     * both as proved when the user comes back, and Never counts neither,
     * so a confirm through it counts toward the session's level alone.
     * Keyring refuses to build one whose freshness is Reauthenticate
     * without supportsReauthentication().
     */
    public function freshness(): SsoFreshness;

    /**
     * Where to send the user, with the request's state, nonce and PKCE
     * challenge, its loginHint where the provider takes one, and for a
     * request with a maxAge, what asks the provider for a sign in that
     * recent.
     */
    public function authorizationUrl(AuthorizationRequest $request): string;

    /**
     * Who the callback says signed in, with when they signed in at the
     * provider (authTime) where it says. The request is the one its state
     * named, already taken from the session.
     *
     * @throws SsoFailed
     */
    public function identify(AuthorizationRequest $request, Request $callback): Identity;
}
