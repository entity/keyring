<?php

declare(strict_types=1);

namespace Keyring\Sso;

use Closure;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use Keyring\Enums\SsoFailure;
use Keyring\Exceptions\SsoFailed;
use Keyring\Support\Duration;
use Throwable;

/**
 * What Keyring reads from identity providers: their discovery documents and
 * signing keys. Both are cached in keyring.sso.store for keyring.sso.cache_for,
 * so a sign in doesn't wait on two more requests. Only once they've been
 * checked: one that's no use isn't kept.
 *
 * A provider rotates its keys by publishing the new one before signing with
 * it. A token signed with a key Keyring hasn't seen sends it back for the
 * keys again, but only once every REFETCH_EVERY seconds for each provider:
 * a stranger making up key IDs can't have Keyring ask the provider for its
 * keys with every request they send.
 */
class Metadata
{
    public const int REFETCH_EVERY = 60;

    public function __construct(
        protected CacheFactory $cache,
    ) {}

    /**
     * Everything the provider says about itself at this URL. $check is
     * given the document before it's cached, and throws for one that's no
     * use, so a bad answer is asked for again next time rather than kept
     * for as long as a good one.
     *
     * @param  (Closure(array<string, mixed>): void)|null  $check
     * @return array<string, mixed>
     *
     * @throws SsoFailed
     */
    public function discover(string $url, ?Closure $check = null): array
    {
        return $this->store()->remember('keyring:sso:discovery:'.hash('sha256', $url), $this->cacheFor(), function () use ($url, $check) {
            $document = $this->fetch($url);

            if ($check !== null) {
                $check($document);
            }

            return $document;
        });
    }

    /**
     * The keys the provider signs with, as published at this URL.
     *
     * @return list<array<array-key, mixed>>
     *
     * @throws SsoFailed
     */
    public function keys(string $url): array
    {
        return $this->store()->remember($this->keysKey($url), $this->cacheFor(), fn () => $this->fetchKeys($url));
    }

    /**
     * The keys read again, past the cache, or null when they were read again
     * too recently to ask once more.
     *
     * @return list<array<array-key, mixed>>|null
     *
     * @throws SsoFailed
     */
    public function refreshKeys(string $url): ?array
    {
        if (! $this->store()->add('keyring:sso:refetched:'.hash('sha256', $url), true, static::REFETCH_EVERY)) {
            return null;
        }

        $keys = $this->fetchKeys($url);
        $this->store()->put($this->keysKey($url), $keys, $this->cacheFor());

        return $keys;
    }

    /**
     * HTTPS, or plain HTTP to this machine for a provider run locally while
     * developing (Keycloak in Docker, say). Anything else could be read or
     * changed on its way.
     *
     * Without $local, this machine isn't allowed at all: for the endpoints
     * a provider elsewhere names, which mustn't be able to point Keyring's
     * requests at the server's own services.
     */
    public static function isSecure(mixed $url, bool $local = true): bool
    {
        if (! is_string($url) || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

        return $local
            ? $scheme === 'https' || ($scheme === 'http' && static::isLocal($url))
            : $scheme === 'https' && ! static::isLocal($url);
    }

    /**
     * Whether the URL is on this machine: localhost, 127.0.0.1 or [::1].
     */
    public static function isLocal(string $url): bool
    {
        return in_array(strtolower((string) parse_url($url, PHP_URL_HOST)), ['localhost', '127.0.0.1', '[::1]'], true);
    }

    /**
     * How Keyring calls a provider: briefly, and only the URL it was given.
     * A redirect isn't followed, so a provider's endpoint can't hand the
     * request, and what's in it, to somewhere else.
     */
    public static function http(): PendingRequest
    {
        return Http::acceptJson()->connectTimeout(5)->timeout(10)->withoutRedirecting();
    }

    /**
     * @return array<string, mixed>
     *
     * @throws SsoFailed
     */
    public function fetch(string $url): array
    {
        if (! static::isSecure($url)) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$url}] is not an HTTPS URL.");
        }

        try {
            $document = static::http()->get($url)->throw()->json();
        } catch (Throwable) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$url}] could not be read.");
        }

        if (! is_array($document) || array_is_list($document)) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$url}] did not answer with a JSON object.");
        }

        return $document;
    }

    /**
     * @return list<array<array-key, mixed>>
     *
     * @throws SsoFailed
     */
    protected function fetchKeys(string $url): array
    {
        $keys = $this->fetch($url)['keys'] ?? null;
        $keys = is_array($keys) && array_is_list($keys) ? array_values(array_filter($keys, is_array(...))) : [];

        // Thrown, so it isn't cached: a provider signs with at least one.
        if ($keys === []) {
            throw SsoFailed::because(SsoFailure::Unavailable, "[{$url}] did not list any keys.");
        }

        return $keys;
    }

    protected function keysKey(string $url): string
    {
        return 'keyring:sso:keys:'.hash('sha256', $url);
    }

    protected function cacheFor(): int
    {
        return Duration::seconds(config('keyring.sso.cache_for'));
    }

    protected function store(): Repository
    {
        return $this->cache->store(config('keyring.sso.store'));
    }
}
