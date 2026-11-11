<?php

declare(strict_types=1);

namespace Keyring\Support;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Cookie as SymfonyCookie;

/**
 * Keyring's own cookies: the device cookie, and the one that ties "remember
 * me" to its session. Both are httpOnly and SameSite=Lax. Wherever the app
 * is served over HTTPS they are Secure too, and named with the prefix that
 * has the browser hold them to it.
 */
final class Cookies
{
    /**
     * Whether the app is served over HTTPS: APP_URL says so, or the session
     * cookie is already kept to it (session.secure). The app's settings
     * decide, not the request. The answer names the cookie, so it has to be
     * the same on every request, and behind a proxy the app doesn't trust
     * every request looks like plain HTTP.
     */
    public static function secure(): bool
    {
        return config('session.secure') === true
            || strtolower((string) parse_url((string) config('app.url'), PHP_URL_SCHEME)) === 'https';
    }

    /**
     * A cookie's name: the app's own, exactly as it set it, or else
     * Keyring's with the prefix the app's setup allows.
     *
     * A browser only takes a "__Host-" cookie that is Secure, for the whole
     * site and from this host alone, so another subdomain or a page sent
     * over plain HTTP can't set or replace it. A cookie shared with
     * subdomains (session.domain), or kept to a path, can only be
     * "__Secure-". Over plain HTTP a browser refuses both, so there the
     * name is left as it is.
     */
    public static function name(?string $configured, string $default): string
    {
        return $configured ?? match (true) {
            ! self::secure() => $default,
            blank(config('session.domain')) && self::path() === '/' => '__Host-'.$default,
            default => '__Secure-'.$default,
        };
    }

    /**
     * Give the browser a cookie, and take back the one it held under the
     * name's earlier form.
     */
    public static function queue(Request $request, string $name, #[\SensitiveParameter] string $value, int $minutes): void
    {
        Cookie::queue(self::make($name, $value, $minutes));

        self::forgetEarlier($request, $name);
    }

    /**
     * Have the browser drop a cookie, under whichever names it sent it. A
     * prefixed cookie is only dropped by a response that is Secure the way
     * the one that set it was, so this is made like that one.
     */
    public static function forget(Request $request, string $name): void
    {
        Cookie::unqueue($name);

        if ($request->cookies->has($name)) {
            Cookie::queue(self::make($name, '', -2628000));
        }

        self::forgetEarlier($request, $name);
    }

    /**
     * What the browser holds under the name without its prefix, when it
     * holds nothing under the name itself: the cookie it was given before
     * the app was served over HTTPS. Another subdomain, or anyone on the
     * network back then, could have set that one, so it only finds what's
     * already there, and whatever it finds moves to today's name.
     */
    public static function earlier(Request $request, string $name): mixed
    {
        $earlier = self::unprefixed($name);

        return $earlier === null || $request->cookies->has($name) ? null : $request->cookie($earlier);
    }

    protected static function forgetEarlier(Request $request, string $name): void
    {
        $earlier = self::unprefixed($name);

        if ($earlier !== null && $request->cookies->has($earlier)) {
            Cookie::queue(self::make($earlier, '', -2628000));
        }
    }

    /**
     * With the path and domain the name was judged by. Where the settings
     * don't say the app is on HTTPS, Secure is left to the request, as
     * Laravel leaves the session cookie's.
     */
    protected static function make(string $name, #[\SensitiveParameter] string $value, int $minutes): SymfonyCookie
    {
        return Cookie::make(
            $name,
            $value,
            $minutes,
            path: self::path(),
            domain: config('session.domain'),
            secure: self::secure() ?: config('session.secure'),
            httpOnly: true,
            sameSite: 'lax',
        );
    }

    protected static function path(): string
    {
        return config('session.path') ?: '/';
    }

    protected static function unprefixed(string $name): ?string
    {
        return match (true) {
            str_starts_with($name, '__Host-') => substr($name, 7),
            str_starts_with($name, '__Secure-') => substr($name, 9),
            default => null,
        };
    }
}
