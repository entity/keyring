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
use Symfony\Component\HttpFoundation\IpUtils;
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

    /**
     * What PHP's global range lets through but isn't anywhere on the
     * internet a provider could be: IPv4-compatible IPv6 (::7f00:1 is
     * 127.0.0.1), the local-use NAT64 prefix, IPv6's old site-local
     * addresses, and multicast.
     */
    protected const array NOT_PUBLIC = ['::/96', '64:ff9b:1::/48', 'fec0::/10', 'ff00::/8', '224.0.0.0/4'];

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
     * HTTPS, or with $local, plain HTTP to this machine for a provider run
     * locally while developing (Keycloak in Docker, say). Anything else
     * could be read or changed on its way.
     *
     * Where the URL points is up to isInward(): an endpoint Keyring sends
     * its own requests to is checked with both.
     */
    public static function isSecure(mixed $url, bool $local = true): bool
    {
        if (! is_string($url) || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));

        return $scheme === 'https' || ($local && $scheme === 'http' && static::isLocal($url));
    }

    /**
     * Whether the URL is on this machine: localhost, 127.0.0.1 or [::1],
     * with or without a trailing dot.
     */
    public static function isLocal(string $url): bool
    {
        return in_array(static::host($url), ['localhost', '127.0.0.1', '::1'], true);
    }

    /**
     * Whether both URLs are on the same host and port, the scheme's own
     * port when they name none.
     */
    public static function sameHost(string $url, string $other): bool
    {
        return static::host($url) === static::host($other) && static::port($url) === static::port($other);
    }

    /**
     * Whether the URL's host is, or resolves to, an address that isn't on
     * the public internet: loopback, private, link-local (169.254.169.254,
     * where clouds keep their metadata), carrier-grade NAT, multicast, or
     * reserved, IPv4 and IPv6 alike, including IPv4 written inside IPv6. A
     * host with a numeric last label is an IPv4 address written some other
     * way (2130706433, 0x7f.1, 0177.0.0.1, 127.1), as a browser or curl
     * would read it, and counts too, as does localhost and anything under
     * it. So does a host with anything but ASCII letters, digits, dots,
     * hyphens and underscores in it: the HTTP client decodes a percent-
     * encoded host (10.0.0.%31) and converts a Unicode one to punycode, so
     * it may reach an address this never saw. A provider can write
     * punycode itself.
     *
     * A name is resolved with HostResolver, and counts when any of its
     * addresses does. One with a dot that doesn't resolve is let through:
     * the request to it fails anyway. One without a dot isn't: the HTTP
     * client may find it where HostResolver didn't look (a hosts file
     * entry only for IPv6, such as ip6-localhost, or a search domain),
     * and a single-label name is never a provider on the internet.
     *
     * This can't stop DNS rebinding. The HTTP client resolves the name
     * again for itself, so a name whose answer changes between the two
     * lookups (a very short TTL, say) can still reach an inward address.
     * It holds against a provider's discovery document naming such an
     * address, or a name that always resolves to one.
     */
    public static function isInward(string $url): bool
    {
        $host = static::host($url);

        if ($host === '' || $host === 'localhost' || str_ends_with($host, '.localhost')) {
            return true;
        }

        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return ! static::isPublic($host);
        }

        if (preg_match('/^[a-z0-9._-]+$/D', $host) !== 1 || preg_match('/(^|\.)(0x[0-9a-f]*|[0-9]+)$/iD', $host) === 1) {
            return true;
        }

        $addresses = app(HostResolver::class)->addresses($host);

        if ($addresses === []) {
            return ! str_contains($host, '.');
        }

        return array_any($addresses, fn (string $address) => ! static::isPublic($address));
    }

    /**
     * Whether the address is on the public internet, as RFC 6890's registry
     * says, and isn't one of NOT_PUBLIC. An IPv6 address on the NAT64
     * prefix (64:ff9b::/96) reaches the IPv4 address in its last 32 bits,
     * so it's held to that one.
     */
    protected static function isPublic(string $address): bool
    {
        $packed = (string) inet_pton($address);

        if (strlen($packed) === 16 && str_starts_with($packed, "\x00\x64\xff\x9b".str_repeat("\0", 8))) {
            $address = (string) inet_ntop(substr($packed, 12));
        }

        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) !== false
            && ! IpUtils::checkIp($address, static::NOT_PUBLIC);
    }

    /**
     * The URL's host in lowercase, without IPv6's brackets or the trailing
     * dot that names the same host.
     */
    protected static function host(string $url): string
    {
        return rtrim(trim(strtolower((string) parse_url($url, PHP_URL_HOST)), '[]'), '.');
    }

    /**
     * The URL's port, or its scheme's when it names none.
     */
    protected static function port(string $url): ?int
    {
        $port = parse_url($url, PHP_URL_PORT);

        return is_int($port) ? $port : match (strtolower((string) parse_url($url, PHP_URL_SCHEME))) {
            'https' => 443,
            'http' => 80,
            default => null,
        };
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
