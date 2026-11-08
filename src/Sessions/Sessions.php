<?php

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Keyring\Contracts\SessionRegistry;
use Keyring\Devices\UserAgent;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Models\Device;
use Keyring\Support\Duration;

/**
 * Starts, finds and ends registered sessions for the current request.
 */
class Sessions
{
    public const string KEY = 'keyring.session';

    public function __construct(
        protected SessionRegistry $registry,
    ) {}

    public function start(Request $request, Authenticatable $user, ?Device $device, Assurance $assurance): RegisteredSession
    {
        $now = now()->getTimestamp();

        $session = new RegisteredSession(
            id: Str::random(40),
            userId: (string) $user->getAuthIdentifier(),
            guard: config('keyring.guard'),
            deviceId: $device?->id,
            assurance: $assurance,
            ip: $request->ip(),
            userAgent: UserAgent::from($request),
            authenticatedAt: $now,
            lastActivityAt: $now,
            expiresAt: $now + $this->absolute($assurance),
        );

        $this->registry->save($session);
        $request->session()->put(self::KEY, $session->id);

        return $session;
    }

    public function current(Request $request): ?RegisteredSession
    {
        $id = $request->session()->get(self::KEY);

        return is_string($id) ? $this->registry->find($id) : null;
    }

    /**
     * Record a step-up. Higher levels may have a shorter absolute timeout.
     */
    public function elevate(Request $request, Assurance $assurance): void
    {
        $session = $this->current($request);

        if ($session !== null && $assurance->value > $session->assurance->value) {
            $this->registry->update($session->id, [
                'assurance' => $assurance,
                'expiresAt' => min($session->expiresAt, $session->authenticatedAt + $this->absolute($assurance)),
            ]);
        }
    }

    public function end(Request $request): void
    {
        $id = $request->session()->pull(self::KEY);

        if (is_string($id)) {
            $this->registry->revoke($id);
        }
    }

    /**
     * Seconds of inactivity allowed at this level, or null for no limit
     * (Laravel's own session lifetime still applies).
     */
    public function idle(Assurance $assurance): ?int
    {
        $idle = $this->timeout($assurance, 'idle');

        return $idle === null ? null : Duration::seconds($idle);
    }

    public function absolute(Assurance $assurance): int
    {
        return Duration::seconds($this->timeout($assurance, 'absolute') ?? '30d');
    }

    /**
     * The level's own timeout (sessions.levels.aal3.idle), else the default.
     */
    protected function timeout(Assurance $assurance, string $kind): int|string|null
    {
        return config('keyring.sessions.levels.'.strtolower($assurance->name).'.'.$kind, config('keyring.sessions.'.$kind));
    }

    /**
     * Sign the user out everywhere but the given session, and close the other
     * ways back in without a full sign in: Laravel keeps one remember token
     * per user, so cycling it stops every "remember me" cookie, and no other
     * device stays trusted.
     */
    public function revokeAll(Authenticatable $user, ?string $except = null): int
    {
        $keptDevice = $except === null ? null : $this->registry->find($except)?->deviceId;
        $count = $this->registry->revokeAll($user, $except);

        $this->cycleRememberToken($user);
        $this->distrustDevices($user, except: $keptDevice);

        return $count;
    }

    public function cycleRememberToken(Authenticatable $user): void
    {
        if ($user->getRememberToken() !== null) {
            $user->setRememberToken(Str::random(60));

            if ($user instanceof Model) {
                $user->save();
            }
        }
    }

    protected function distrustDevices(Authenticatable $user, ?string $except): void
    {
        if ($user instanceof Model) {
            Keyring::deviceModel()::query()
                ->ownedBy($user)
                ->whereNotNull('trusted_until')
                ->when($except, fn (Builder $query) => $query->whereKeyNot($except))
                ->update(['trusted_until' => null]);
        }
    }

    public function registry(): SessionRegistry
    {
        return $this->registry;
    }
}
