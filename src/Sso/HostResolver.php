<?php

declare(strict_types=1);

namespace Keyring\Sso;

use Closure;
use Illuminate\Container\Attributes\Scoped;

/**
 * The addresses a host name resolves to, for Metadata to tell whether an
 * endpoint a provider names points back inside the server's network.
 *
 * Each name is looked up once for as long as the resolver lives, which is
 * one request: a callback checks the token endpoint and the key set's URL,
 * often on the same host, more than once.
 *
 * HostResolver::fake() answers from a list instead, so tests never ask the
 * network's DNS. FakeIdentityProvider calls it for you, with no host
 * resolving to anything.
 */
#[Scoped]
class HostResolver
{
    /**
     * The names looked up so far, with what they resolved to.
     *
     * @var array<string, list<string>>
     */
    protected array $resolved = [];

    /**
     * @param  (Closure(string): list<string>)|null  $using
     */
    public function __construct(
        protected ?Closure $using = null,
    ) {}

    /**
     * Answer from $hosts, each name's list of addresses, from now on in
     * this app. A name that isn't there resolves to nothing.
     *
     * @param  array<string, list<string>>  $hosts
     */
    public static function fake(array $hosts = []): self
    {
        $resolver = new self(fn (string $host) => $hosts[$host] ?? []);

        app()->instance(self::class, $resolver);

        return $resolver;
    }

    /**
     * Every IPv4 and IPv6 address the name has, or none when it can't be
     * resolved.
     *
     * @return list<string>
     */
    public function addresses(string $host): array
    {
        return $this->resolved[$host] ??= $this->lookUp($host);
    }

    /**
     * @return list<string>
     */
    protected function lookUp(string $host): array
    {
        if ($this->using !== null) {
            return ($this->using)($host);
        }

        // @codeCoverageIgnoreStart
        // It asks the network's DNS, which no test does. A lookup that
        // fails warns, and counts as resolving to nothing.
        $ipv4 = @gethostbynamel($host) ?: [];
        $ipv6 = @dns_get_record($host, DNS_AAAA) ?: [];

        return [...$ipv4, ...array_values(array_filter(array_column($ipv6, 'ipv6'), is_string(...)))];
        // @codeCoverageIgnoreEnd
    }
}
