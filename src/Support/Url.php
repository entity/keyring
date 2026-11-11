<?php

declare(strict_types=1);

namespace Keyring\Support;

use DateTimeInterface;
use Illuminate\Http\Request;
use Illuminate\Routing\UrlGenerator;
use Keyring\Facades\Keyring;

/**
 * Links in emails are built from APP_URL (or Keyring::linkRootUsing()) and
 * nothing in the request that caused the email: not its Host header, and not
 * a forwarded prefix. A forged header can't redirect a reset link or end up
 * in what a signed link signs. Signed links sign only the path and query, so
 * routes check them with `signed:relative`.
 */
final class Url
{
    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function route(string $name, array $parameters = []): string
    {
        return Keyring::linkRoot().self::generator()->route($name, $parameters, absolute: false);
    }

    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function signed(string $name, DateTimeInterface $expires, array $parameters = []): string
    {
        return Keyring::linkRoot().self::generator()->temporarySignedRoute($name, $expires, $parameters, absolute: false);
    }

    /**
     * Laravel's URL generator as it would be for a plain request to the link
     * root. The app's own builds a route's path on the current request, so
     * what a proxy header added to that request would come along.
     */
    protected static function generator(): UrlGenerator
    {
        return tap(clone app(UrlGenerator::class))->setRequest(Request::create(Keyring::linkRoot()));
    }
}
