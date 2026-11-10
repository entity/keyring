<?php

namespace Keyring\Support;

use Closure;
use DateTimeInterface;
use Illuminate\Support\Facades\URL as Generator;

/**
 * Links in emails are built from APP_URL, never from the request's Host
 * header, so a forged Host can't redirect reset links. Signed links
 * sign only the path and query, so routes check them with `signed:relative`.
 */
final class Url
{
    /** @var (Closure(): string)|null */
    protected static ?Closure $root = null;

    /**
     * Where the links start, in place of APP_URL: for an app on several
     * domains, the one this user is on. Never take it from the Host header.
     *
     * @param  (Closure(): string)|null  $callback
     */
    public static function rootUsing(?Closure $callback): void
    {
        self::$root = $callback;
    }

    public static function root(): string
    {
        return rtrim((string) (self::$root === null ? config('app.url') : (self::$root)()), '/');
    }

    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function route(string $name, array $parameters = []): string
    {
        return self::root().route($name, $parameters, absolute: false);
    }

    /**
     * @param  array<string, mixed>  $parameters
     */
    public static function signed(string $name, DateTimeInterface $expires, array $parameters = []): string
    {
        return self::root().Generator::temporarySignedRoute($name, $expires, $parameters, absolute: false);
    }
}
