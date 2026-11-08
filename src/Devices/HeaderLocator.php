<?php

namespace Keyring\Devices;

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;

/**
 * Reads the location headers a proxy like Cloudflare adds. Only trust these
 * when requests can't reach your app without going through the proxy.
 * Without such headers, locations are simply unknown.
 */
class HeaderLocator implements LocatesIps
{
    public function locate(Request $request): ?array
    {
        $location = array_filter([
            'country' => $request->header('CF-IPCountry'),
            'region' => $request->header('CF-Region'),
            'city' => $request->header('CF-IPCity'),
            'latitude' => $request->header('CF-IPLatitude') === null ? null : (float) $request->header('CF-IPLatitude'),
            'longitude' => $request->header('CF-IPLongitude') === null ? null : (float) $request->header('CF-IPLongitude'),
        ], fn ($value) => ! in_array($value, [null, '', 'XX'], true));

        return $location === [] ? null : $location;
    }
}
