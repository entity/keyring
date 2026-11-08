<?php

namespace Keyring\Support;

/**
 * Links in emails are built from APP_URL, never from the request's Host
 * header, so a forged Host can't redirect reset links (OWASP).
 */
final class Url
{
    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function route(string $name, array $parameters = []): string
    {
        return rtrim((string) config('app.url'), '/').route($name, $parameters, absolute: false);
    }
}
