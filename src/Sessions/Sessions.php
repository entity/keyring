<?php

namespace Keyring\Sessions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Session\CookieSessionHandler;
use Illuminate\Support\Str;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Devices\UserAgent;
use Keyring\Enums\Assurance;
use Keyring\Facades\Keyring;
use Keyring\Features;
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
            expiresAt: $now + $this->absolute(),
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
     * Record the level a step-up reached, for the sessions list. The session
     * keeps its own limits; levels lapse on their own (SessionAssurance).
     */
    public function elevate(Request $request, Assurance $assurance): void
    {
        $session = $this->current($request);

        if ($session !== null && $assurance->value > $session->assurance->value) {
            $this->registry->update($session->id, ['assurance' => $assurance]);
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
     * Give the current session a new ID, so a copy of it made before now
     * stops working. Regenerating destroys the old session on the server. A
     * cookie session lives in the browser, where nothing can destroy a copy,
     * so its registry record is swapped for a new one and the old one revoked.
     */
    public function rotate(Request $request): void
    {
        $session = $this->current($request);

        if ($session !== null && $request->session()->getHandler() instanceof CookieSessionHandler) {
            $this->registry->save($rotated = $session->with(['id' => Str::random(40)]));
            $this->registry->revoke($session->id);

            $request->session()->put(self::KEY, $rotated->id);
        }

        $request->session()->regenerate(true);
    }

    /**
     * Seconds of inactivity allowed before the session ends, or with a level,
     * before that level lapses. Null for no limit (Laravel's own session
     * lifetime still applies).
     */
    public function idle(?Assurance $level = null): ?int
    {
        $idle = $this->timeout($level, 'idle');

        return $idle === null ? null : Duration::seconds($idle);
    }

    /**
     * Seconds after sign in that the session ends, or with a level, that a
     * verification keeps counting toward it.
     */
    public function absolute(?Assurance $level = null): int
    {
        return Duration::seconds($this->timeout($level, 'absolute') ?? '30d');
    }

    /**
     * The level's own limit (sessions.levels.aal2.idle), else the session's.
     */
    protected function timeout(?Assurance $level, string $kind): int|string|null
    {
        $default = config('keyring.sessions.'.$kind);

        return $level === null ? $default : config('keyring.sessions.levels.'.strtolower($level->name).'.'.$kind, $default);
    }

    /**
     * Sign the user out everywhere but the given session, and close the other
     * ways back in without a full sign in: Laravel keeps one remember token
     * per user, so cycling it stops every "remember me" cookie, no other
     * device stays trusted, and an email change waiting for confirmation is
     * cancelled, though its "this wasn't me" link keeps working.
     */
    public function revokeAll(Authenticatable $user, ?string $except = null): int
    {
        $keptDevice = $except === null ? null : $this->registry->find($except)?->deviceId;
        $count = $this->registry->revokeAll($user, $except);

        $this->cycleRememberToken($user);
        $this->distrustDevices($user, except: $keptDevice);
        $this->cancelEmailChanges($user);

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

    /**
     * Stop trusting the user's devices, or all but one. Does nothing when
     * devices are off, so a security change can't fail on tables never used.
     */
    public function distrustDevices(Authenticatable $user, ?string $except = null): void
    {
        if ($user instanceof Model && Features::enabled(Features::devices())) {
            Keyring::deviceModel()::query()
                ->ownedBy($user)
                ->whereNotNull('trusted_until')
                ->when($except, fn (Builder $query) => $query->whereKeyNot($except))
                ->update(['trusted_until' => null]);
        }
    }

    protected function cancelEmailChanges(Authenticatable $user): void
    {
        if ($user instanceof Model) {
            // Resolved here because EmailChanges needs this class.
            app(EmailChanges::class)->cancel($user);
        }
    }

    public function registry(): SessionRegistry
    {
        return $this->registry;
    }
}
