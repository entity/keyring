<?php

declare(strict_types=1);

namespace Keyring\Models\Concerns;

/**
 * Tokens go out in plain text, in a cookie or an emailed link, and are
 * stored as SHA-256 hashes. They're long and random, so a plain hash is
 * enough to stop a copy of the table being used to forge one.
 */
trait HashesTokens
{
    public static function hashToken(#[\SensitiveParameter] string $token): string
    {
        return hash('sha256', $token);
    }
}
