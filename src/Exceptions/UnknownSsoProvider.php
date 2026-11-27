<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use InvalidArgumentException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * An identity provider that isn't in keyring.sso.providers. Their names
 * come from URLs, so in a request this is a 404.
 */
class UnknownSsoProvider extends InvalidArgumentException implements HttpExceptionInterface
{
    public static function named(string $name): self
    {
        return new self("Identity provider [{$name}] is not configured in keyring.sso.providers.");
    }

    public function getStatusCode(): int
    {
        return 404;
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return [];
    }
}
