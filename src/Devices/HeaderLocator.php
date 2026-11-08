<?php

namespace Keyring\Devices;

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;

/**
 * Reads the location headers a proxy adds (Cloudflare's by default). Only
 * trust these when requests can't reach your app without going through
 * the proxy. Without such headers, locations are simply unknown.
 *
 *     $this->app->bind(LocatesIps::class, fn () => new HeaderLocator(['country' => 'X-Country-Code']));
 */
class HeaderLocator implements LocatesIps
{
    /**
     * @param  array<string, string>  $headers  location field => header name
     */
    public function __construct(
        protected array $headers = [
            'country' => 'CF-IPCountry',
            'region' => 'CF-Region',
            'city' => 'CF-IPCity',
            'latitude' => 'CF-IPLatitude',
            'longitude' => 'CF-IPLongitude',
        ],
    ) {}

    public function locate(Request $request): ?array
    {
        $location = [];

        foreach ($this->headers as $field => $header) {
            $value = $request->header($header);

            // "XX" is Cloudflare's "unknown".
            if (! in_array($value, [null, '', 'XX'], true)) {
                $location[$field] = in_array($field, ['latitude', 'longitude'], true) ? (float) $value : $value;
            }
        }

        return $location === [] ? null : $location;
    }
}
