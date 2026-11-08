<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Keyring\Devices\DeviceManager;
use Keyring\Events\RiskAssessed;
use Keyring\KeyringManager;
use Keyring\Risk\Assessment;
use Keyring\Risk\Checkpoint;
use Keyring\Risk\RiskEngine;
use Keyring\Session\SessionAssurance;
use Keyring\Sessions\RegisteredSession;
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
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $guard = $this->keyring->guard();

        if (! $request->hasSession() || ! $guard->check()) {
            return $next($request);
        }

        $user = $guard->user();
        $session = $this->sessions->current($request);

        // Signed in some other way (e.g. a "remember me" cookie): register it,
        // with no verifications, so sensitive routes still ask for a factor.
        if ($session === null) {
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

        if ($this->risk->hasRequestSignals() && ($response = $this->assessRisk($request, $user, $session)) !== null) {
            return $response;
        }

        if ($now - $session->lastActivityAt >= 60) {
            $this->sessions->registry()->touch($session->id, $now);
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

        if (! $risk->isElevated()) {
            return null;
        }

        $action = $this->risk->decide($risk, Checkpoint::Request);

        if ($action->doesSomething()) {
            RiskAssessed::dispatch($user, $risk, $action, Checkpoint::Request->value);
        }

        if ($action->revokeSessions) {
            $this->sessions->registry()->revokeAll($user);
            $this->devices->cycleRememberToken($user);
        }

        if ($action->reauthenticate || $action->deny || $action->revokeSessions) {
            return $this->signOut($request);
        }

        // Ask again before anything sensitive, and remember what we've seen
        // so the same change isn't acted on twice.
        if ($action->stepUp) {
            $this->assurance->flush();
        }

        $this->sessions->registry()->save($session->with([
            'ip' => $request->ip(),
            'userAgent' => Str::limit((string) $request->userAgent(), 500, ''),
        ]));

        return null;
    }

    protected function signOut(Request $request): Response
    {
        $this->sessions->end($request);
        $this->keyring->guard()->logout();
        $this->assurance->flush();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        if ($request->expectsJson() && ! $request->hasHeader('X-Inertia')) {
            return new JsonResponse(['message' => __('keyring::keyring.signed_out')], 401);
        }

        return redirect()->guest(route('login'))->with('status', __('keyring::keyring.signed_out'));
    }
}
