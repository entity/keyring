<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Devices\DeviceManager;
use Keyring\Devices\UserAgent;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\RiskEngine;
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
    use ChoosesFormat;

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected SessionAssurance $assurance,
        protected DeviceManager $devices,
        protected RiskEngine $risk,
        protected SignIn $signIn,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $guard = $this->keyring->guard();

        if (! $request->hasSession() || ! $guard->check()) {
            return $next($request);
        }

        $user = $guard->user();
        $session = $this->sessions->current($request);

        if ($session === null) {
            // The session was registered, but its record is gone (revoked and
            // expired, or the store was cleared). Treat it as signed out rather
            // than starting it over with a fresh window.
            if ($request->session()->has(Sessions::KEY)) {
                return $this->signOut($request);
            }

            // Signed in some other way (e.g. a "remember me" cookie): register it.
            $this->sessions->start($request, $user, $this->devices->find($request, $user), $this->assurance->level());

            return $next($request);
        }

        $now = now()->getTimestamp();
        $idle = $this->sessions->idle($session->assurance);

        if (
            ! $session->isActive($now)
            || $session->userId !== (string) $user->getAuthIdentifier()
            || ($idle !== null && $now - $session->lastActivityAt > $idle)
        ) {
            return $this->signOut($request);
        }

        if ($this->risk->signalsFor(Checkpoint::Request) !== [] && ($response = $this->assessRisk($request, $user, $session)) !== null) {
            return $response;
        }

        if ($now - $session->lastActivityAt >= 60) {
            $this->sessions->registry()->update($session->id, ['lastActivityAt' => $now]);
        }

        return $next($request);
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
            return $this->signOut($request);
        }

        // Ask again before anything sensitive, and remember what we've seen
        // so the same change isn't acted on twice.
        if ($action->stepUp) {
            $this->assurance->flush();
        }

        if ($action->doesSomething()) {
            $this->sessions->registry()->update($session->id, [
                'ip' => $request->ip(),
                'userAgent' => UserAgent::from($request),
            ]);
        }

        return null;
    }

    protected function signOut(Request $request): Response
    {
        $this->signIn->out($request);

        // Like Laravel's own auth middleware: 401 for JSON, otherwise back to
        // login, remembering where they were going.
        if ($this->wantsJson($request)) {
            return new JsonResponse(['status' => 'signed-out', 'message' => $this->keyring->statusMessage('signed-out')], 401);
        }

        return redirect()->guest(route('login'))->with('status', 'signed-out');
    }
}
