<?php

namespace Keyring\Support;

/**
 * HMAC-SHA256 with the app key, for values Keyring stores only to look up or
 * compare later (recovery codes, reserved addresses).
 */
final class KeyedHash
{
    public static function make(string $value, ?string $key = null): string
    {
        return hash_hmac('sha256', $value, $key ?? config('app.key'));
    }

    /**
     * The value hashed with the current key and every previous one, so
     * rotating APP_KEY (with APP_PREVIOUS_KEYS) keeps stored hashes working.
     *
     * @return list<string>
     */
    public static function candidates(string $value): array
    {
        return array_map(
            fn (string $key) => self::make($value, $key),
            [config('app.key'), ...config('app.previous_keys', [])],
        );
    }
}
