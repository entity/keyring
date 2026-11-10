<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Contracts\Responses\SignedOutResponse;
use Keyring\Devices\DeviceManager;
use Keyring\Devices\UserAgent;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\Events\SessionEnded;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\RiskEngine;
use Keyring\Risk\RiskLocks;
use Keyring\Sessions\RegisteredSession;
use Keyring\Sessions\SessionAssurance;
use Keyring\Sessions\Sessions;
use Symfony\Component\HttpFoundation\Response;

/**
 * Checks every signed-in request against the session registry, so revoking
 * a session or device takes effect straight away on any session driver.
 * Also enforces idle and absolute timeouts.
 */
class AuthenticateSession
{
    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected SessionAssurance $assurance,
        protected DeviceManager $devices,
        protected RiskEngine $risk,
        protected RiskLocks $locks,
        protected SignIn $signIn,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $guard = $this->keyring->guard();

        if (! $request->hasSession()) {
            return $next($request);
        }

        // An app's own Auth::login() (Socialite, impersonation) is registered
        // on the response that signs in, so every copy of that session's
        // cookie can be revoked, on the cookie driver too. One that ticked
        // "remember me" gets Keyring's cookie next to Laravel's.
        if (! $guard->check()) {
            return tap($next($request), function () use ($request, $guard) {
                if (($user = $guard->user()) !== null && ! $request->session()->has(Sessions::KEY)) {
                    $this->register($request, $user, remembered: $this->sessions->recallerQueued());
                }
            });
        }

        $user = $this->keyring->user();
        $session = $this->sessions->current($request);

        if ($session === null) {
            // The session was registered, but its record is gone (revoked and
            // expired, or the store was cleared). Treat it as signed out rather
            // than starting it over with a fresh window.
            if ($request->session()->has(Sessions::KEY)) {
                return $this->signOut($request, 'revoked');
            }

            if ($this->recalled($request)) {
                return $this->resume($request, $user) ?? $next($request);
            }

            $this->register($request, $user);

            return $next($request);
        }

        $now = now()->getTimestamp();

        if (($ended = $this->ended($session, $user, $now)) !== null) {
            return $this->signOut($request, $ended);
        }

        // Before anything checks the level, so inactivity lapses it first.
        $this->assurance->touch();

        if ($this->risk->signalsFor(Checkpoint::Request) !== [] && ($response = $this->assessRisk($request, $user, $session)) !== null) {
            return $response;
        }

        if ($now - $session->lastActivityAt >= 60) {
            $this->sessions->registry()->update($session->id, ['lastActivityAt' => $now]);
        }

        return $next($request);
    }

    /**
     * Why this user can't carry on with a record, if they can't.
     *
     * @return 'revoked'|'expired'|'idle'|'other_user'|null
     */
    protected function ended(RegisteredSession $session, Authenticatable $user, int $now): ?string
    {
        $idle = $this->sessions->idle();

        return match (true) {
            $session->revokedAt !== null => 'revoked',
            ! $session->isActive($now) => 'expired',
            $session->userId !== (string) $user->getAuthIdentifier() => 'other_user',
            $idle !== null && $now - $session->lastActivityAt > $idle => 'idle',
            default => null,
        };
    }

    /**
     * Register a session that started some other way, like an app's own
     * Auth::login().
     */
    protected function register(Request $request, Authenticatable&Model $user, bool $remembered = false): void
    {
        $this->sessions->start($request, $user, $this->devices->find($request, $user), $this->assurance->level(), $remembered);
        $this->assurance->touch();
    }

    /**
     * Whether a "remember me" cookie signed this session in: on this request,
     * or earlier on a route this middleware isn't on (Sessions::markRecalled).
     */
    protected function recalled(Request $request): bool
    {
        return $this->keyring->guard()->viaRemember() || $request->session()->get(Sessions::REMEMBERED) === true;
    }

    /**
     * Let a "remember me" cookie carry on the session it was issued with, and
     * nothing else. Laravel's cookie works for as long as the browser sends
     * it, so on its own a copy kept after a timeout or a risk response would
     * start a new session with a whole new window. The browser's Keyring
     * cookie names the record it goes with, and the record has to still be
     * good. Returns a response when it isn't.
     */
    protected function resume(Request $request, Authenticatable&Model $user): ?Response
    {
        // The cookie signs in with nothing proved, so a risk lock refuses it
        // like any other sign in.
        if ($this->locks->locked($user)) {
            return $this->signOut($request, 'risk');
        }

        $session = $this->sessions->remembered($request);

        // No cookie, or no record left for it: both are kept for as long as
        // the session could last, so it has run out.
        if ($session === null) {
            return $this->signOut($request, 'expired');
        }

        if (($ended = $this->ended($session, $user, now()->getTimestamp())) !== null) {
            // An idle session ends for good, as when its own request shows it.
            if ($ended === 'idle') {
                $this->sessions->registry()->revoke($session->id);
            }

            return $this->signOut($request, $ended);
        }

        // Recorded like a sign in, so a browser the account hasn't used is
        // announced as a new device.
        $device = $this->devices->signIn($request, $user);

        // Whatever this session held, the cookie proved none of it.
        $this->assurance->flush();
        $this->sessions->resume($request, $session, $device);
        $this->assurance->touch();

        if ($device?->wasRecentlyCreated) {
            NewDeviceSignedIn::dispatch($user, $device);
        }

        return null;
    }

    /**
     * Cheap mid-session checks, like the session cookie turning up in a
     * different browser. Returns a response when the session must end.
     */
    protected function assessRisk(Request $request, mixed $user, RegisteredSession $session): ?Response
    {
        $risk = $this->risk->assess(new Assessment(Checkpoint::Request, $request, $user, session: $session));
        $action = $this->risk->enforce($user, $risk, Checkpoint::Request);

        if ($action->reauthenticate || $action->deny || $action->revokeSessions) {
            return $this->signOut($request, 'risk');
        }

        if (! $action->doesSomething()) {
            return null;
        }

        // Remember what we've seen, so the same change isn't acted on twice.
        $seen = ['ip' => $this->keyring->recordedIp($request), 'userAgent' => UserAgent::from($request)];

        // Ask again before anything sensitive. Only this request's copy of
        // the session forgets what it proved, so the session gets a new
        // record: an older cookie, or a request that overlapped this one and
        // saves after it, holds the old one and is signed out.
        if ($action->stepUp) {
            $this->assurance->flush();
            $this->sessions->reregister($request, $seen);
        } else {
            $this->sessions->registry()->update($session->id, $seen);
        }

        return null;
    }

    /**
     * @param  'revoked'|'expired'|'idle'|'other_user'|'risk'  $reason
     */
    protected function signOut(Request $request, string $reason): Response
    {
        if ($user = $this->signIn->out($request, onlyThisBrowser: true)) {
            SessionEnded::dispatch($user, $reason);
        }

        return $this->keyring->response(SignedOutResponse::class, reason: $reason)->toResponse($request);
    }
}
