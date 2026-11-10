<?php

namespace Keyring\Devices;

use Illuminate\Http\Request;
use Illuminate\Support\Str;

/**
 * Just enough user agent parsing to name a device for humans ("Firefox on
 * Windows"). The name is also a weak risk signal (a session's browser
 * changing), never a factor. Plug in a real parser with
 * Keyring::describeDevicesUsing().
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

    /**
     * The request's user agent, trimmed for storage.
     */
    public static function from(Request $request): ?string
    {
        return Str::limit(mb_scrub((string) $request->userAgent()), 500, '') ?: null;
    }

    public static function describe(?string $userAgent): ?string
    {
        if ($userAgent === null || $userAgent === '') {
            return null;
        }

        $browser = self::match(self::BROWSERS, $userAgent);
        $platform = self::match(self::PLATFORMS, $userAgent);

        if ($browser === null || $platform === null) {
            return $browser ?? $platform;
        }

        return trans('keyring::keyring.device_name', ['browser' => $browser, 'platform' => $platform]);
    }

    /**
     * @param  array<string, string>  $patterns
     */
    private static function match(array $patterns, string $userAgent): ?string
    {
        return array_find_key($patterns, fn (string $pattern) => preg_match($pattern, $userAgent) === 1);
    }
}
