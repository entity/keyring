<?php

namespace Keyring\Devices;

/**
 * Just enough user agent parsing to name a device for humans
 * ("Firefox on Windows"). Never used for security decisions.
 */
final class UserAgent
{
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

    public static function describe(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $browser = self::match(self::BROWSERS, $userAgent);
        $platform = self::match(self::PLATFORMS, $userAgent);

        return match (true) {
            $browser !== null && $platform !== null => __(':browser on :platform', ['browser' => $browser, 'platform' => $platform]),
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
