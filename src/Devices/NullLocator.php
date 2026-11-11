<?php

declare(strict_types=1);

namespace Keyring\Devices;

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;

class NullLocator implements LocatesIps
{
    public function locate(Request $request): ?array
    {
        return null;
    }
}
