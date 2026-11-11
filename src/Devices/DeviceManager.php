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
use Keyring\Features;
use Keyring\KeyringManager;
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
        protected KeyringManager $keyring,
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

        return $token === null ? new EloquentCollection : $this->keyring->deviceModel()::query()
            ->withToken($token)
            ->active()
            ->get();
    }

    /**
     * Record a sign in from this browser and return its device, or null when
     * the feature is off. One the account hasn't used before was just
     * created, so $device->wasRecentlyCreated says whether it's new.
     *
     * A sign in that proved a second factor gives the browser a new cookie,
     * and only one of those may mark the device trusted.
     */
    public function signIn(Request $request, Authenticatable&Model $user, bool $provedSecondFactor = false, bool $trust = false): ?Device
    {
        if (! Features::enabled(Features::devices())) {
            return null;
        }

        $device = $this->find($request, $user) ?? $this->newDevice($request, $user);

        $device->fill([
            'name' => $this->keyring->describeDevice($request->userAgent()),
            'user_agent' => UserAgent::from($request),
            'ip' => $this->keyring->recordedIp($request),
            'location' => Location::of($request) ?? $device->location,
            'last_seen_at' => now(),
        ]);

        if ($provedSecondFactor) {
            $this->rotateToken($request, $device);
        }

        if ($provedSecondFactor && $trust && ($for = config('keyring.devices.trust_for')) !== null) {
            $device->trusted_until = Duration::fromNow($for);
        }

        $device->save();

        if ($device->wasRecentlyCreated) {
            $this->forgetOldest($user, $device);
        }

        return $device;
    }

    /**
     * Keep an account to "devices.limit" devices: a new one beyond that
     * takes the place of whichever was seen longest ago, which is signed
     * out and forgotten. Every sign in from a browser without the cookie
     * makes a device, so without a limit one account could fill the table,
     * and its own devices page, just by signing in.
     */
    protected function forgetOldest(Authenticatable&Model $user, Device $new): void
    {
        if (($limit = config('keyring.devices.limit')) === null) {
            return;
        }

        // Every one past the limit, should it have been lowered: skip()
        // needs a take() on some databases, so the rest are simply named.
        $oldest = $this->keyring->deviceModel()::query()
            ->ownedBy($user)
            ->active()
            ->whereKeyNot($new->getKey())
            ->latest('last_seen_at')
            ->latest('id')
            ->skip(max(0, (int) $limit - 1))
            ->take(PHP_INT_MAX)
            ->pluck('id');

        foreach ($oldest as $id) {
            $this->sessions->revokeDevice($user, $id);
        }

        $this->keyring->deviceModel()::query()->whereKey($oldest->all())->delete();
    }

    /**
     * An unsaved device for a browser the account hasn't used before, with
     * its cookie queued.
     */
    protected function newDevice(Request $request, Authenticatable&Model $user): Device
    {
        $token = $this->tokenForNewDevice($request, $user);

        $device = new ($this->keyring->deviceModel())([
            'token_hash' => $this->keyring->deviceModel()::hashToken($token),
            'first_seen_at' => now(),
        ]);

        $this->queueCookie($token);

        return $device->authenticatable()->associate($user);
    }

    /**
     * Sign the device out everywhere and stop trusting it, whatever state
     * its account is in: a deactivated one may be restored.
     */
    public function revoke(Device $device, bool $reported = false): void
    {
        $device->forceFill(['revoked_at' => now(), 'trusted_until' => null])->save();

        if ($user = $device->owner()) {
            $this->sessions->revokeDevice($user, $device->id);
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
        $sessions = $this->sessions->active($user)->groupBy(fn (RegisteredSession $session) => $session->deviceId ?? '');

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
        $hash = $this->keyring->deviceModel()::hashToken($token);

        if (($presented = $this->token($request)) !== null) {
            $this->keyring->deviceModel()::query()->withToken($presented)->active()->update(['token_hash' => $hash]);
        }

        $device->token_hash = $hash;

        $this->queueCookie($token);
    }

    protected function queueCookie(#[\SensitiveParameter] string $token): void
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
        return $this->keyring->deviceModel()::query()->ownedBy($user);
    }
}
