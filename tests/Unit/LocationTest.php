<?php

use Illuminate\Http\Request;
use Keyring\Contracts\LocatesIps;
use Keyring\Devices\HeaderLocator;
use Keyring\Devices\Location;

it('reads the headers it is told to, skipping unknowns', function () {
    $request = Request::create('/', server: ['HTTP_X_COUNTRY' => 'GB', 'HTTP_X_LAT' => '51.5', 'HTTP_CF_IPCOUNTRY' => 'XX']);

    expect(new HeaderLocator(['country' => 'X-Country', 'latitude' => 'X-Lat'])->locate($request))->toBe(['country' => 'GB', 'latitude' => 51.5])
        ->and(new HeaderLocator()->locate($request))->toBeNull();
});

it('locates each request once, however many times it is asked', function () {
    $locator = new class implements LocatesIps
    {
        public int $calls = 0;

        public function locate(Request $request): array
        {
            $this->calls++;

            return ['country' => 'GB'];
        }
    };
    app()->instance(LocatesIps::class, $locator);
    $request = Request::create('/');

    Location::of($request);
    expect(Location::of($request))->toBe(['country' => 'GB'])
        ->and($locator->calls)->toBe(1);
});
