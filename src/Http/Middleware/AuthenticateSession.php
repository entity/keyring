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
        // cookie can be revoked, on the cookie driver too.
        if (! $guard->check()) {
            return tap($next($request), function () use ($request, $guard) {
                if (($user = $guard->user()) !== null && ! $request->session()->has(Sessions::KEY)) {
                    $this->register($request, $user, remembered: false);
                }
            });
        }

        $user = $guard->user();
        $session = $this->sessions->current($request);

        if ($session === null) {
            // The session was registered, but its record is gone (revoked and
            // expired, or the store was cleared). Treat it as signed out rather
            // than starting it over with a fresh window.
            if ($request->session()->has(Sessions::KEY)) {
                return $this->signOut($request, 'revoked');
            }

            // A "remember me" cookie signs in with nothing proved, so a risk
            // lock refuses it like any other sign in.
            if ($guard->viaRemember() && $this->locks->locked($user)) {
                return $this->signOut($request, 'risk');
            }

            $this->register($request, $user, $guard->viaRemember());

            return $next($request);
        }

        $now = now()->getTimestamp();
        $idle = $this->sessions->idle();

        $ended = match (true) {
            $session->revokedAt !== null => 'revoked',
            ! $session->isActive($now) => 'expired',
            $session->userId !== (string) $user->getAuthIdentifier() => 'other_user',
            $idle !== null && $now - $session->lastActivityAt > $idle => 'idle',
            default => null,
        };

        if ($ended !== null) {
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
     * Register a session that started some other way. A "remember me" cookie
     * is recorded like a sign in, so one turning up in a browser the account
     * hasn't used is announced as a new device.
     */
    protected function register(Request $request, Authenticatable&Model $user, bool $remembered): void
    {
        $device = $remembered
            ? $this->devices->signIn($request, $user)
            : $this->devices->find($request, $user);

        $this->sessions->start($request, $user, $device, $this->assurance->level());
        $this->assurance->touch();

        if ($device?->wasRecentlyCreated) {
            NewDeviceSignedIn::dispatch($user, $device);
        }
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

        // Ask again before anything sensitive, and remember what we've seen
        // so the same change isn't acted on twice.
        if ($action->stepUp) {
            $this->assurance->flush();
        }

        if ($action->doesSomething()) {
            $this->sessions->registry()->update($session->id, [
                'ip' => $this->keyring->recordedIp($request),
                'userAgent' => UserAgent::from($request),
            ]);
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
