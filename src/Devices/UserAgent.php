<?php

namespace Keyring\Devices;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * Just enough user agent parsing to name a device for humans ("Firefox on
 * Windows"). The name is also a weak risk signal (a session's browser
 * changing), never a factor. Plug in a real parser with describeUsing().
 */
final class UserAgent
{
    /** @var (Closure(string): ?string)|null */
    private static ?Closure $describer = null;

    private const array BROWSERS = [
        'Edge' => '/Edg(e|A|iOS)?\//',
        'Opera' => '/OPR\/|Opera/',
        'Samsung Internet' => '/SamsungBrowser/',
        'Firefox' => '/Firefox\/|FxiOS/',
        'Chrome' => '/Chrome\/|CriOS/',
        'Safari' => '/Safari\//',
    ];

    private const array PLATFORMS = [
        'iPhone' => '/iPhone/',
        'iPad' => '/iPad/',
        'Android' => '/Android/',
        'ChromeOS' => '/CrOS/',
        'Windows' => '/Windows/',
        'macOS' => '/Macintosh|Mac OS X/',
        'Linux' => '/Linux/',
    ];

    /**
     * @param  (Closure(string): ?string)|null  $describer
     */
    public static function describeUsing(?Closure $describer): void
    {
        self::$describer = $describer;
    }

    /**
     * The request's user agent, trimmed for storage.
     */
    public static function from(Request $request): ?string
    {
        return Str::limit((string) $request->userAgent(), 500, '') ?: null;
    }

    public static function describe(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        if (self::$describer !== null) {
            return (self::$describer)($userAgent);
        }

        $browser = self::match(self::BROWSERS, $userAgent);
        $platform = self::match(self::PLATFORMS, $userAgent);

        return match (true) {
            $browser !== null && $platform !== null => __('keyring::keyring.device_name', ['browser' => $browser, 'platform' => $platform]),
            default => $browser ?? $platform,
        };
    }

    /**
     * @param  array<string, string>  $patterns
     */
    private static function match(array $patterns, string $userAgent): ?string
    {
        return array_find_key($patterns, fn (string $pattern) => preg_match($pattern, $userAgent) === 1);
    }
}
