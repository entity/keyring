<?php

namespace Keyring\Devices;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Collection as EloquentCollection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Str;
use Keyring\Events\DeviceRevoked;
use Keyring\Facades\Keyring;
use Keyring\Features;
use Keyring\Models\Device;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\Sessions;
use Keyring\Support\Duration;

/**
 * Recognises devices by a long-lived, httpOnly cookie (stored hashed), with
 * Features::devices(). Without it, no device is ever recorded or found.
 */
class DeviceManager
{
    public function __construct(
        protected Sessions $sessions,
    ) {}

    /**
     * The user's device for this browser, if it's been seen before.
     */
    public function find(Request $request, Authenticatable&Model $user): ?Device
    {
        return $this->forBrowser($request)->first(fn (Device $device) => $device->authenticatable()->is($user));
    }

    /**
     * Every account's device for this browser. The cookie is shared by
     * everyone who signs in on it, so there can be more than one.
     *
     * @return EloquentCollection<int, Device>
     */
    public function forBrowser(Request $request): EloquentCollection
    {
        $token = Features::enabled(Features::devices()) ? $this->token($request) : null;

        return $token === null ? new EloquentCollection : Keyring::deviceModel()::query()
            ->withToken($token)
            ->active()
            ->get();
    }

    /**
     * Record a sign in from this browser. Returns the device and whether it's
     * new, or no device when the feature is off.
     *
     * @return array{0: ?Device, 1: bool}
     */
    public function signIn(Request $request, Authenticatable&Model $user, bool $trust = false, bool $fullSignIn = false): array
    {
        if (! Features::enabled(Features::devices())) {
            return [null, false];
        }

        $device = $this->find($request, $user);
        $new = $device === null;

        if ($new) {
            $token = $this->tokenForNewDevice($request, $user);

            $device = Keyring::deviceModel()::make(['token_hash' => Keyring::deviceModel()::hashToken($token), 'first_seen_at' => now()]);
            $device->authenticatable()->associate($user);

            $this->queueCookie($token);
        }

        $device->fill([
            'name' => UserAgent::describe($request->userAgent()),
            'user_agent' => UserAgent::from($request),
            'ip' => Keyring::recordedIp($request),
            'location' => Location::of($request) ?? $device->location,
            'last_seen_at' => now(),
        ]);

        if ($trust && ($for = config('keyring.devices.trust_for')) !== null) {
            $device->trusted_until = Duration::fromNow($for);
        }

        if ($trust || $fullSignIn) {
            $this->rotateToken($request, $device);
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
            $this->sessions->registry()->revokeDevice($user, $device->id);
            $this->sessions->cycleRememberToken($user);

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
        $sessions = $this->sessions->registry()->forUser($user)->groupBy(fn (RegisteredSession $session) => $session->deviceId);

        return $this->query($user)
            ->active()
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

    public function token(Request $request): ?string
    {
        $token = $request->cookie($this->cookie());

        return is_string($token) && strlen($token) === 40 ? $token : null;
    }

    public function cookie(): string
    {
        return config('keyring.devices.cookie');
    }

    /**
     * A new random token, unless another account already has a device with
     * the one this browser sent: the cookie is shared by everyone signing in
     * on the browser, so that one is kept. A value no account has is never
     * stored. The server can't tell a shared cookie from one planted in this
     * browser with a value another account holds, so a kept token only gets
     * the device recognised until a login proves a second factor (rotateToken).
     */
    protected function tokenForNewDevice(Request $request, Authenticatable&Model $user): string
    {
        $token = $this->token($request);

        // A revoked device starts over with a new token.
        return $token !== null && $this->forBrowser($request)->isNotEmpty() && ! $this->query($user)->withToken($token)->exists()
            ? $token
            : Str::random(40);
    }

    /**
     * Neither trust nor a proven second factor may rest on a token the browser
     * could have been handed, so both issue a new one. Everyone signed in on
     * this browser moves to it together, or the cookie would stop matching
     * their devices.
     */
    protected function rotateToken(Request $request, Device $device): void
    {
        $token = Str::random(40);
        $hash = Keyring::deviceModel()::hashToken($token);

        if (($presented = $this->token($request)) !== null) {
            Keyring::deviceModel()::query()->withToken($presented)->active()->update(['token_hash' => $hash]);
        }

        $device->token_hash = $hash;

        $this->queueCookie($token);
    }

    protected function queueCookie(string $token): void
    {
        Cookie::queue(Cookie::make(
            $this->cookie(),
            $token,
            minutes: intdiv(Duration::seconds(config('keyring.devices.cookie_lifetime')), 60),
            secure: config('session.secure'),
            httpOnly: true,
            sameSite: 'lax',
        ));
    }

    /**
     * @return Builder<Device>
     */
    protected function query(Authenticatable&Model $user): Builder
    {
        return Keyring::deviceModel()::query()->ownedBy($user);
    }
}
