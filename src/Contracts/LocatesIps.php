<?php

namespace Keyring\Contracts;

use Illuminate\Http\Request;

/**
 * Works out roughly where a request came from. Bind your own (MaxMind, an
 * API...) to show locations on devices and power location risk signals.
 */
interface LocatesIps
{
    /**
     * @return array{country?: string, region?: string, city?: string, latitude?: float, longitude?: float}|null
     */
    public function locate(Request $request): ?array;
}
