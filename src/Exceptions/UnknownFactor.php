<?php

declare(strict_types=1);

namespace Keyring\Exceptions;

use InvalidArgumentException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;

/**
 * A factor key that isn't registered. Factor keys come from URLs, so in a
 * request this is a 404.
 */
class UnknownFactor extends InvalidArgumentException implements HttpExceptionInterface
{
    public static function named(string $key): self
    {
        return new self("Factor [{$key}] is not registered with Keyring.");
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
