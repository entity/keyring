<?php

declare(strict_types=1);

namespace Keyring\Sessions;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\SessionGuard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Session\CookieSessionHandler;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Str;
use Keyring\Changes\PendingEmailChanges;
use Keyring\Contracts\SessionRegistry;
use Keyring\Devices\UserAgent;
use Keyring\Enums\Assurance;
use Keyring\Features;
use Keyring\KeyringManager;
use Keyring\Models\Device;
use Keyring\Support\Cookies;
use Keyring\Support\Duration;
use Keyring\Support\Throttle;

/**
 * Starts, finds and ends registered sessions for the current request.
 */
class Sessions
{
    public const string KEY = 'keyring.session';

    /**
     * Set on a session "remember me" may bring back. On one with no record
     * yet, a "remember me" cookie signed it in and the record it goes with
     * is still to be found (AuthenticateSession).
     */
    public const string REMEMBERED = 'keyring.remembered';

    public function __construct(
        protected SessionRegistry $registry,
        protected KeyringManager $keyring,
        protected PendingEmailChanges $emailChanges,
    ) {}

    public function start(Request $request, Authenticatable $user, ?Device $device, Assurance $assurance, bool $remembered = false): RegisteredSession
    {
        $now = now()->getTimestamp();

        $session = new RegisteredSession(
            id: Str::random(40),
            userId: (string) $user->getAuthIdentifier(),
            guard: config('keyring.guard'),
            deviceId: $device?->id,
            assurance: $assurance,
            ip: $this->keyring->recordedIp($request),
            userAgent: UserAgent::from($request),
            authenticatedAt: $now,
            lastActivityAt: $now,
            expiresAt: $now + $this->absolute(),
        );

        $this->registry->save($session);
        $this->bind($request, $session, $remembered);

        return $session;
    }

    /**
     * Carry a remembered session on in the new session its "remember me"
     * cookie signed in, under a new record and a new cookie. The cookie that
     * came is used up: a copy of it brings nothing back. The new record is a
     * copy of the old, so it keeps the limits it started with, but its
     * address and browser are this request's. The cookie proved nothing, so
     * the level starts again.
     *
     * Null when the record couldn't be replaced: a request sent alongside
     * this one used the cookie first, or the session was just revoked.
     */
    public function resume(Request $request, RegisteredSession $session): ?RegisteredSession
    {
        $current = $session->with([
            'id' => Str::random(40),
            'assurance' => Assurance::None,
            'ip' => $this->keyring->recordedIp($request),
            'userAgent' => UserAgent::from($request),
            'lastActivityAt' => now()->getTimestamp(),
        ]);

        if (! $this->registry->replace($session->id, $current)) {
            return null;
        }

        $this->bind($request, $current, remembered: true);

        return $current;
    }

    /**
     * The session a request may join when the cookie it came with was used
     * up a moment ago. A browser coming back often sends several requests at
     * once, all with the same cookie. The first replaces it, and the rest
     * belong on that session, not signed out.
     *
     * Only within "sessions.remember_grace" of the cookie being replaced,
     * however often it's sent, and only for the browser that replaced it:
     * the same cookie from two browsers is two holders, however close
     * together. Null for anything else.
     */
    public function overlapped(Request $request, RegisteredSession $replaced): ?RegisteredSession
    {
        if ($replaced->replacedBy === null || now()->getTimestamp() - (int) $replaced->replacedAt >= Duration::seconds(config('keyring.sessions.remember_grace') ?? 0)) {
            return null;
        }

        $session = $this->registry->find($replaced->replacedBy);

        return $session?->userAgent === UserAgent::from($request) ? $session : null;
    }

    /**
     * Put a request on the session one sent alongside it resumed
     * (overlapped). Nothing is registered and the record stays as that
     * request left it, so a used cookie can't start a session of its own.
     */
    public function join(Request $request, RegisteredSession $session): void
    {
        $this->bind($request, $session, remembered: true);
    }

    /**
     * The session a replaced record became, however many times it has moved
     * since. Null when that record is gone.
     */
    public function latest(RegisteredSession $session): ?RegisteredSession
    {
        while ($session?->replacedBy !== null) {
            $session = $this->registry->find($session->replacedBy);
        }

        return $session;
    }

    /**
     * Point the request's session at its record. A remembered one also gets
     * the cookie that lets "remember me" bring it back.
     */
    protected function bind(Request $request, RegisteredSession $session, bool $remembered): void
    {
        $request->session()->put(self::KEY, $session->id);

        if (! $remembered) {
            $request->session()->forget(self::REMEMBERED);

            return;
        }

        $request->session()->put(self::REMEMBERED, true);
        $this->queueRememberCookie($request, $session);
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

        $request->session()->forget(self::REMEMBERED);
        $this->forgetRememberCookie($request);
    }

    /**
     * Give the current session a new ID, so a copy of it made before now
     * stops working. Regenerating destroys the old session on the server. A
     * cookie session lives in the browser, where nothing can destroy a copy,
     * so its registry record is swapped for a new one and the old one revoked.
     */
    public function rotate(Request $request): void
    {
        if ($request->session()->getHandler() instanceof CookieSessionHandler) {
            $this->reregister($request);
        }

        $request->session()->regenerate(true);
    }

    /**
     * Swap the session's registry record for a new one and revoke the old.
     * Only this request's copy of the session learns the new ID, so any
     * other copy from before now (an older cookie, a request that overlapped
     * and saves later) is signed out when it's next used. The old record
     * names the new one, so a "remember me" cookie used up before the swap
     * can still be followed to the session it became (latest).
     *
     * @param  array<string, mixed>  $changes
     */
    public function reregister(Request $request, array $changes = []): void
    {
        $session = $this->current($request);

        // One that has ended, or moved on without this request, isn't brought back.
        if ($session === null || ! $this->registry->replace($session->id, $current = $session->with(['id' => Str::random(40), ...$changes]), revoke: true)) {
            return;
        }

        // The browser's "remember me" moves to the new record with it.
        $this->bind($request, $current, $request->session()->get(self::REMEMBERED) === true);
    }

    /**
     * The record this browser's "remember me" belongs to, if there still is
     * one. Another guard's record doesn't count: its users can have the same
     * IDs as this one's.
     */
    public function remembered(Request $request): ?RegisteredSession
    {
        $id = $request->cookie($this->rememberCookie()) ?? Cookies::earlier($request, $this->rememberCookie());
        $session = is_string($id) && strlen($id) === 40 ? $this->registry->find($id) : null;

        return $session?->guard === config('keyring.guard') ? $session : null;
    }

    /**
     * Whether this response gives the browser Laravel's "remember me" cookie,
     * as an app's own Auth::login($user, remember: true) does. Signing out
     * queues one too, with nothing in it.
     */
    public function recallerQueued(): bool
    {
        $guard = $this->keyring->guard();

        return $guard instanceof SessionGuard && filled(Cookie::queued($guard->getRecallerName())?->getValue());
    }

    /**
     * Note that a "remember me" cookie signed the session in, as it happens.
     * The guard only knows for the rest of that request, and on a route
     * without Keyring's middleware the next one would find a signed-in
     * session with nothing to say how it started.
     *
     * The guard announces the cookie as a login that ticked "remember me",
     * and it can say it came by the cookie when the cookie was refused and
     * someone then signed in. A real login that ticked it has a new cookie
     * queued by now.
     */
    public function markRecalled(Login $event): void
    {
        $guard = $this->keyring->guard();

        if ($event->guard === config('keyring.guard') && $event->remember && $guard instanceof SessionGuard && $guard->viaRemember() && ! $this->recallerQueued()) {
            $guard->getSession()->put(self::REMEMBERED, true);
        }
    }

    /**
     * "sessions.remember_cookie", or keyring_remember with the prefix the
     * app's setup allows: __Host-keyring_remember over HTTPS.
     */
    public function rememberCookie(): string
    {
        return Cookies::name(config('keyring.sessions.remember_cookie'), 'keyring_remember');
    }

    /**
     * Laravel's "remember me" cookie is the same in every browser a user
     * ticked it in, and nothing on the server makes it run out. This one
     * names the record it was issued with, so "remember me" can only bring
     * that session back, and only for as long as the record lasts.
     */
    protected function queueRememberCookie(Request $request, RegisteredSession $session): void
    {
        Cookies::queue($request, $this->rememberCookie(), $session->id, minutes: max(1, (int) ceil(($session->expiresAt - now()->getTimestamp()) / 60)));
    }

    protected function forgetRememberCookie(Request $request): void
    {
        Cookies::forget($request, $this->rememberCookie());
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
    public function signOutEverywhere(Authenticatable $user, ?string $except = null): int
    {
        $keptDevice = $except === null ? null : $this->registry->find($except)?->deviceId;
        $count = $this->registry->revokeAll($user, $except);

        $this->cycleRememberToken($user);
        $this->distrustDevices($user, except: $keptDevice);

        if ($user instanceof Model) {
            $this->emailChanges->cancel($user);
        }

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
     * Stop trusting the user's devices, or all but one, and stop any of them
     * counting as a known browser for rate limits until it signs in again.
     * Does nothing when devices are off, so a security change can't fail on
     * tables never used.
     */
    public function distrustDevices(Authenticatable $user, ?string $except = null): void
    {
        if ($user instanceof Model && Features::enabled(Features::devices())) {
            app(Throttle::class)->forgetBrowsers($user);

            $this->keyring->deviceModel()::query()
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
