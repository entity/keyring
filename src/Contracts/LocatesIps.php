<?php

declare(strict_types=1);

namespace Keyring\Contracts;

use Illuminate\Http\Request;

/**
 * Works out roughly where a request came from. Bind your own (MaxMind, an
 * API...) to show locations on devices and power location risk signals.
 */
interface LocatesIps
{
    /**
     * Whichever of these is known: country, region, city, and latitude and
     * longitude as floats. Null when nothing is.
     *
     * @return array<string, mixed>|null
     */
    public function locate(Request $request): ?array;
}
