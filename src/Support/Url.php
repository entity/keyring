<?php

namespace Keyring\Support;

use DateTimeInterface;
use Illuminate\Support\Facades\URL as Generator;

/**
 * Links in emails are built from APP_URL, never from the request's Host
 * header, so a forged Host can't redirect reset links. Signed links
 * sign only the path and query, so routes check them with `signed:relative`.
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

    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function signed(string $name, DateTimeInterface $expires, array $parameters = []): string
    {
        return rtrim((string) config('app.url'), '/').Generator::temporarySignedRoute($name, $expires, $parameters, absolute: false);
    }
}
