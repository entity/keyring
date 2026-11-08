<?php

namespace Keyring\Devices;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Str;
use Keyring\Contracts\LocatesIps;
use Keyring\Contracts\SessionRegistry;
use Keyring\Events\DeviceRevoked;
use Keyring\Models\Device;
use Keyring\Sessions\RegisteredSession;
use Keyring\Support\Duration;

/**
 * Recognises devices by a long-lived, httpOnly cookie (stored hashed).
 */
class DeviceManager
{
    public function __construct(
        protected LocatesIps $locator,
        protected SessionRegistry $sessions,
    ) {}

    /**
     * The user's device for this browser, if it's been seen before.
     */
    public function find(Request $request, Authenticatable&Model $user): ?Device
    {
        $token = $this->token($request);

        if ($token === null) {
            return null;
        }

        return $this->query($user)
            ->where('token_hash', hash('sha256', $token))
            ->whereNull('revoked_at')
            ->first();
    }

    /**
     * Record a sign in from this browser. Returns the device and whether it's new.
     *
     * @return array{0: Device, 1: bool}
     */
    public function signIn(Request $request, Authenticatable&Model $user, bool $trust = false): array
    {
        $device = $this->find($request, $user);
        $new = $device === null;

        if ($new) {
            $token = $this->token($request) ?? Str::random(40);

            // A revoked device starts over with a new token.
            if ($this->query($user)->where('token_hash', hash('sha256', $token))->exists()) {
                $token = Str::random(40);
            }

            $device = new Device(['token_hash' => hash('sha256', $token), 'first_seen_at' => now()]);
            $device->authenticatable()->associate($user);

            $this->queueCookie($token);
        }

        $device->fill([
            'name' => UserAgent::describe($request->userAgent()),
            'user_agent' => Str::limit((string) $request->userAgent(), 500, ''),
            'ip' => $request->ip(),
            'location' => $this->locator->locate($request) ?? $device->location,
            'last_seen_at' => now(),
        ]);

        if ($trust && ($for = config('keyring.devices.trust_for')) !== null) {
            $device->trusted_until = now()->addSeconds(Duration::seconds($for));
        }

        $device->save();

        return [$device, $new];
    }

    /**
     * Sign the device out everywhere and stop trusting it.
     */
    public function revoke(Device $device, bool $reported = false): void
    {
        $device->forceFill(['revoked_at' => now(), 'trusted_until' => null])->save();

        if ($user = $device->user()) {
            $this->sessions->revokeDevice($user, $device->id);
            $this->cycleRememberToken($user);

            DeviceRevoked::dispatch($user, $device, $reported);
        }
    }

    /**
     * The user's devices with their active sessions, for a "where you're
     * signed in" page.
     *
     * @return Collection<int, array{id: string, name: ?string, description: string, ip: ?string, location: ?array<string, mixed>, lastActiveAt: ?string, trusted: bool, current: bool, sessions: int}>
     */
    public function list(Request $request, Authenticatable&Model $user): Collection
    {
        $current = $this->find($request, $user)?->id;
        $sessions = $this->sessions->forUser($user)->groupBy(fn (RegisteredSession $session) => $session->deviceId);

        return $this->query($user)
            ->whereNull('revoked_at')
            ->orderByDesc('last_seen_at')
            ->get()
            ->map(fn (Device $device) => [
                'id' => $device->id,
                'name' => $device->name,
                'description' => $device->description(),
                'ip' => $device->ip,
                'location' => $device->location,
                'lastActiveAt' => $device->last_seen_at?->toIso8601String(),
                'trusted' => $device->isTrusted(),
                'current' => $device->id === $current,
                'sessions' => count($sessions->get($device->id, [])),
            ]);
    }

    /**
     * Laravel has one remember token per user, so changing it signs out every
     * "remember me" cookie at once.
     */
    public function cycleRememberToken(Authenticatable $user): void
    {
        if ($user->getRememberToken() !== null) {
            $user->setRememberToken(Str::random(60));

            if ($user instanceof Model) {
                $user->save();
            }
        }
    }

    public function token(Request $request): ?string
    {
        $token = $request->cookie($this->cookie());

        return is_string($token) && strlen($token) === 40 ? $token : null;
    }

    public function cookie(): string
    {
        return config('keyring.devices.cookie', 'keyring_device');
    }

    protected function queueCookie(string $token): void
    {
        Cookie::queue(Cookie::make(
            $this->cookie(),
            $token,
            minutes: 60 * 24 * 400,
            secure: config('session.secure'),
            httpOnly: true,
            sameSite: 'lax',
        ));
    }

    /**
     * @return Builder<Device>
     */
    protected function query(Authenticatable&Model $user)
    {
        return Device::query()->whereMorphedTo('authenticatable', $user);
    }
}
