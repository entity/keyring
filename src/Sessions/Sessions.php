<?php

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Keyring\Contracts\SessionRegistry;
use Keyring\Enums\Assurance;
use Keyring\Models\Device;
use Keyring\Support\Duration;

/**
 * Starts, finds and ends registered sessions for the current request.
 */
class Sessions
{
    public const KEY = 'keyring.session';

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
            userAgent: Str::limit((string) $request->userAgent(), 500, ''),
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
            $this->registry->save($session->with([
                'assurance' => $assurance,
                'expiresAt' => min($session->expiresAt, $session->authenticatedAt + $this->absolute($assurance)),
            ]));
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
        $idle = config('keyring.sessions.levels.'.strtolower($assurance->name).'.idle', config('keyring.sessions.idle'));

        return $idle === null ? null : Duration::seconds($idle);
    }

    public function absolute(Assurance $assurance): int
    {
        return Duration::seconds(config(
            'keyring.sessions.levels.'.strtolower($assurance->name).'.absolute',
            config('keyring.sessions.absolute', '30d'),
        ));
    }

    public function registry(): SessionRegistry
    {
        return $this->registry;
    }
}
