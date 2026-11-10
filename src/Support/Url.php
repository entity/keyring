<?php

namespace Keyring\Support;

use DateTimeInterface;
use Illuminate\Support\Facades\URL as Generator;
use Keyring\Facades\Keyring;

/**
 * Links in emails are built from APP_URL (or Keyring::linkRootUsing()),
 * never from the request's Host header, so a forged Host can't redirect reset links. Signed links
 * sign only the path and query, so routes check them with `signed:relative`.
 */
final class Url
{
    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function route(string $name, array $parameters = []): string
    {
        return Keyring::linkRoot().route($name, $parameters, absolute: false);
    }

    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function signed(string $name, DateTimeInterface $expires, array $parameters = []): string
    {
        return Keyring::linkRoot().Generator::temporarySignedRoute($name, $expires, $parameters, absolute: false);
    }
}
