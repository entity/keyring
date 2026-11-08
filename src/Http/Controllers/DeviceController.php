<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Devices\DeviceManager;
use Keyring\Events\SessionsRevoked;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Models\Device;
use Keyring\Sessions\Sessions;

/**
 * Where the user is signed in, and signing devices out.
 */
class DeviceController
{
    use ChoosesFormat;

    public function __construct(
        protected DeviceManager $devices,
        protected Sessions $sessions,
    ) {}

    public function index(Request $request): JsonResponse
    {
        return new JsonResponse(['devices' => $this->devices->list($request, $request->user())]);
    }

    /**
     * Sign one device out.
     */
    public function destroy(Request $request, string $device): mixed
    {
        $device = Device::query()->whereMorphedTo('authenticatable', $request->user())->whereNull('revoked_at')->findOrFail($device);
        $current = $this->devices->find($request, $request->user())?->id === $device->id;

        $this->devices->revoke($device);

        if ($current) {
            return $this->wantsJson($request)
                ? new JsonResponse(['status' => 'device-revoked', 'redirect' => route('login')])
                : redirect()->route('login');
        }

        return $this->respond($request, 'device-revoked');
    }

    /**
     * Sign out everywhere except here.
     */
    public function destroyOthers(Request $request): mixed
    {
        $user = $request->user();
        $current = $this->sessions->current($request);

        $count = $this->sessions->registry()->revokeAll($user, except: $current?->id);
        $this->devices->cycleRememberToken($user);

        SessionsRevoked::dispatch($user, $count);

        return $this->respond($request, 'sessions-revoked');
    }

    /**
     * The page the signed "this wasn't me" link opens. It changes nothing;
     * its button POSTs back to the same signed URL.
     */
    public function page(Request $request, KeyringManager $keyring, string $device): mixed
    {
        $device = Device::query()->findOrFail($device);

        return $keyring->render('device-report', [
            'device' => $device->description(),
            'url' => $request->getRequestUri(),
        ]);
    }

    /**
     * Sign the reported device out.
     */
    public function report(Request $request, string $device): mixed
    {
        $device = Device::query()->findOrFail($device);

        if (! $device->isRevoked()) {
            $this->devices->revoke($device, reported: true);
        }

        return redirect()->route('login')->with('status', __('keyring::keyring.device_reported'));
    }

    protected function respond(Request $request, string $status): mixed
    {
        return $this->wantsJson($request) ? new JsonResponse(['status' => $status]) : back()->with('status', $status);
    }
}
