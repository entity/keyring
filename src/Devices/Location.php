<?php

namespace Keyring\Devices;

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;

/**
 * Where a request seems to come from, looked up once per request (the
 * locator may call an API), whoever asks first.
 */
final class Location
{
    /**
     * @return array<string, mixed>|null
     */
    public static function of(Request $request): ?array
    {
        if (! $request->attributes->has('keyring.location')) {
            $request->attributes->set('keyring.location', app(LocatesIps::class)->locate($request));
        }

        return $request->attributes->get('keyring.location');
    }
}
