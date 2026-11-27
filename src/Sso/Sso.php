<?php

declare(strict_types=1);

namespace Keyring\Sso;

use Closure;
use Illuminate\Container\Attributes\Singleton;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use InvalidArgumentException;
use Keyring\Contracts\IdentityProvider;
use Keyring\Enums\SsoFailure;
use Keyring\Enums\SsoFreshness;
use Keyring\Exceptions\SsoFailed;
use Keyring\Exceptions\UnknownSsoProvider;
use Keyring\Sso\Providers\GitHubProvider;
use Keyring\Sso\Providers\GoogleProvider;
use Keyring\Sso\Providers\MicrosoftProvider;
use Keyring\Sso\Providers\OidcProvider;
use Throwable;

/**
 * The identity providers in keyring.sso.providers, and the two halves of
 * signing in with one: sending the user there, and taking them back.
 *
 *     return redirect()->away(Keyring::sso()->start('google', 'login', route('sso.callback', 'google')));
 *
 *     $identity = Keyring::sso()->complete($request, 'google');
 *
 * Providers are built from the config each time they're asked for, so a
 * change to it (in a test, say) is seen straight away, and nothing about
 * one request is kept for the next under Octane. Only the drivers apps
 * register are kept.
 */
#[Singleton]
class Sso
{
    /** @var array<string, Closure(array<string, mixed>, string): IdentityProvider> */
    protected array $drivers = [];

    /**
     * Register a driver of your own, or replace one of Keyring's: oidc,
     * google, microsoft or github. The resolver is given the provider's
     * config and its name.
     *
     * @param  Closure(array<string, mixed>, string): IdentityProvider  $resolver
     */
    public function extend(string $driver, Closure $resolver): static
    {
        $this->drivers[$driver] = $resolver;

        return $this;
    }

    public function has(string $name): bool
    {
        return is_array($this->providerConfig()[$name] ?? null);
    }

    /**
     * @throws UnknownSsoProvider when it isn't configured
     */
    public function provider(string $name): IdentityProvider
    {
        $config = $this->providerConfig()[$name] ?? null;

        if (! is_array($config)) {
            throw UnknownSsoProvider::named($name);
        }

        // The name goes in the routes' URLs, which take no other.
        if (preg_match('/^[A-Za-z0-9_-]+$/D', $name) !== 1) {
            throw new InvalidArgumentException("Identity provider [{$name}] has a name with more than letters, digits, - and _.");
        }

        $driver = $config['driver'] ?? null;

        $provider = match (true) {
            is_string($driver) && isset($this->drivers[$driver]) => ($this->drivers[$driver])($config, $name),
            $driver === 'oidc' => new OidcProvider($name, $config),
            $driver === 'google' => new GoogleProvider($name, $config),
            $driver === 'microsoft' => new MicrosoftProvider($name, $config),
            $driver === 'github' => new GitHubProvider($name, $config),
            default => throw new InvalidArgumentException("Identity provider [{$name}] has no driver Keyring knows."),
        };

        if ($provider->name() !== $name) {
            throw new InvalidArgumentException("Identity provider configured as [{$name}] reports the name [{$provider->name()}].");
        }

        $this->resolveFreshness($name, $config, $provider);

        return $provider;
    }

    /**
     * How much a sign in or a confirm through the provider counts toward a
     * fresh verification: its "freshness" in the config, with the driver's
     * freshness() only as the default. So a driver of your own can't leave
     * out what the config says, and a value that isn't one is refused.
     *
     * @throws UnknownSsoProvider when it isn't configured
     * @throws InvalidArgumentException for a provider that can't be built,
     *                                  or a freshness it can't have
     */
    public function freshness(string $name): SsoFreshness
    {
        $provider = $this->provider($name);

        return $this->resolveFreshness($name, $this->providerConfig()[$name], $provider);
    }

    /**
     * @param  array<array-key, mixed>  $config
     *
     * @throws InvalidArgumentException
     */
    protected function resolveFreshness(string $name, array $config, IdentityProvider $provider): SsoFreshness
    {
        $freshness = SsoFreshness::configured($config['freshness'] ?? null, $name, $provider->freshness());

        // A provider that can't be asked for a new sign in would have every
        // confirm through it fail, and no sign in through it count.
        if ($freshness === SsoFreshness::Reauthenticate && ! $provider->supportsReauthentication()) {
            throw new InvalidArgumentException("Identity provider [{$name}] can't be asked for a new sign in, so its \"freshness\" can't be reauthenticate.");
        }

        return $freshness;
    }

    /**
     * Every configured provider, in the config's order, for the buttons on
     * a login page. One that can't be built, such as one whose client_id
     * comes from an env var that isn't set, is reported and left out, so
     * it doesn't take the login page down with it. Asked for by name, it
     * still throws.
     *
     * @return Collection<string, IdentityProvider>
     */
    public function providers(): Collection
    {
        return new Collection($this->names())
            ->mapWithKeys(function (string $name) {
                try {
                    return [$name => $this->provider($name)];
                } catch (Throwable $e) {
                    report($e);

                    return [];
                }
            });
    }

    /**
     * The name of every configured provider, in the config's order, without
     * building any of them.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return array_map(strval(...), array_keys(array_filter($this->providerConfig(), is_array(...))));
    }

    /**
     * Start signing in with a provider: the URL to send the user to. The
     * request is kept in the session, and $redirectUri, which has to be
     * registered with the provider exactly as it's given here, is where it
     * sends them back to. The purpose and data come back with the identity.
     *
     * With $maxAge, the user has to have signed in at the provider no more
     * than that many seconds before they were sent there, and 0 has them
     * sign in again there and then. complete() refuses an identity without
     * an authTime that recent. Only a provider that
     * supportsReauthentication() can be asked. $loginHint is the account
     * they should sign in with, for a provider that takes a login_hint.
     *
     * @param  array<string, mixed>  $data
     *
     * @throws SsoFailed when the provider's metadata can't be read
     * @throws InvalidArgumentException for a $maxAge the provider can't be asked for
     */
    public function start(string $provider, string $purpose, string $redirectUri, array $data = [], ?int $maxAge = null, ?string $loginHint = null): string
    {
        $identityProvider = $this->provider($provider);

        if ($maxAge !== null && ($maxAge < 0 || ! $identityProvider->supportsReauthentication())) {
            throw new InvalidArgumentException("Identity provider [{$provider}] can't be asked for a sign in no older than [{$maxAge}] seconds.");
        }

        $request = AuthorizationRequest::make($provider, $purpose, $redirectUri, $data, $maxAge, $loginHint);

        // The URL first, so a provider that can't be reached leaves nothing
        // in the session.
        $url = $identityProvider->authorizationUrl($request);

        app(PendingAuthorizations::class)->put($request);

        return $url;
    }

    /**
     * Who the provider sent back, from its callback to the redirect URI.
     * The request its state names is taken from the session first, so it's
     * spent whether or not the rest succeeds, and it has to have been
     * started for this provider: a callback can't be finished at another
     * one's. One started with a maxAge has to come back with an authTime
     * within it of when the user was sent there, give or take
     * OidcProvider::LEEWAY, and not in the future.
     *
     * @throws SsoFailed
     */
    public function complete(Request $callback, string $provider): Identity
    {
        $identityProvider = $this->provider($provider);

        $state = $callback->query('state');
        $request = is_string($state) && $state !== '' ? app(PendingAuthorizations::class)->pull($state) : null;

        if ($request === null) {
            throw SsoFailed::because(SsoFailure::InvalidState, 'The callback\'s state is missing, unknown, already used or expired.');
        }

        if ($request->provider !== $provider) {
            throw SsoFailed::because(SsoFailure::InvalidState, "The callback for [{$provider}] has the state of a sign in with [{$request->provider}].");
        }

        $identity = $identityProvider->identify($request, $callback);

        if ($request->maxAge !== null && ! $this->recentEnough($identity->authTime, $request)) {
            throw SsoFailed::because(SsoFailure::StaleAuthentication, $identity->authTime === null
                ? "[{$provider}] didn't say when the user signed in, which a request with max_age needs. Have it send auth_time in its ID tokens, or set the provider's \"freshness\" to \"never\"."
                : "[{$provider}] says the user signed in longer ago than the request's max_age.");
        }

        return $identity;
    }

    /**
     * Whether a sign in at the provider at $authTime is no more than the
     * request's maxAge seconds older than the request, and not in the
     * future, give or take the clocks' leeway. It's measured from when the
     * user was sent there, as max_age is, so however long they take at the
     * provider doesn't count against it.
     */
    protected function recentEnough(?int $authTime, AuthorizationRequest $request): bool
    {
        return $authTime !== null
            && $authTime >= $request->createdAt - (int) $request->maxAge - OidcProvider::LEEWAY
            && $authTime <= now()->getTimestamp() + OidcProvider::LEEWAY;
    }

    /**
     * @return array<array-key, mixed>
     */
    protected function providerConfig(): array
    {
        $providers = config('keyring.sso.providers');

        return is_array($providers) ? $providers : [];
    }
}
