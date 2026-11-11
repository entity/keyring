<?php

declare(strict_types=1);

namespace Keyring\Devices;

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;

/**
 * Where a request seems to come from, looked up once per request (the
 * locator may call an API), whoever asks first. A locator that fails is
 * reported, and the location is unknown for that request. So is one that
 * can't be stored, since a header can carry what JSON can't.
 */
final class Location
{
    /**
     * @return array<string, mixed>|null
     */
    public static function of(Request $request): ?array
    {
        if (! $request->attributes->has('keyring.location')) {
            $request->attributes->set('keyring.location', rescue(function () use ($request) {
                $location = app(LocatesIps::class)->locate($request);

                return json_encode($location) === false ? null : $location;
            }));
        }

        return $request->attributes->get('keyring.location');
    }
}
