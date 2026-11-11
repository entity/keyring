<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Devices\DeviceManager;
use Keyring\Events\SessionsRevoked;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Sessions\Sessions;

/**
 * Where the user is signed in, and signing devices out.
 */
class DeviceController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected DeviceManager $devices,
        protected Sessions $sessions,
    ) {}

    public function index(Request $request): JsonResponse
    {
        return new JsonResponse(['devices' => $this->devices->list($request, $this->keyring->user())]);
    }

    /**
     * Sign one device out. Signing out this one ends this session too.
     */
    public function destroy(Request $request, SignIn $signIn, string $device): StatusResponse
    {
        $device = $this->keyring->deviceModel()::query()->ownedBy($this->keyring->user())->active()->find($device)
            ?? $this->keyring->deviceModel()::refuse($this->keyring->user(), $device);
        $current = $this->devices->find($request, $this->keyring->user())?->is($device);

        $this->devices->revoke($device);

        if ($current) {
            $signIn->out($request);

            return $this->status('device-revoked', redirect: route('login'));
        }

        return $this->status('device-revoked');
    }

    /**
     * Sign out everywhere except here.
     */
    public function destroyOthers(Request $request): StatusResponse
    {
        $count = $this->sessions->signOutEverywhere($this->keyring->user(), except: $this->sessions->current($request)?->id);

        // Someone who copied this session's cookie doesn't get to stay either.
        $this->sessions->rotate($request);

        SessionsRevoked::dispatch($this->keyring->user(), $count);

        return $this->status('sessions-revoked');
    }

    /**
     * The page the signed "this wasn't me" link opens. It changes nothing;
     * its button POSTs back to the same signed URL.
     */
    public function page(Request $request, string $device): mixed
    {
        $device = $this->keyring->deviceModel()::query()->findOrFail($device);

        return $this->keyring->render('device-report', [
            'device' => $device->description(),
            'url' => $request->getRequestUri(),
        ]);
    }

    /**
     * Sign the reported device out.
     */
    public function report(string $device): StatusResponse
    {
        $device = $this->keyring->deviceModel()::query()->findOrFail($device);

        if (! $device->isRevoked()) {
            $this->devices->revoke($device, reported: true);
        }

        return $this->status('device-reported', redirect: route('login'));
    }
}
