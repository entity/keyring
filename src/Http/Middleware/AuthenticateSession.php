<?php

namespace Keyring\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Devices\DeviceManager;
use Keyring\KeyringManager;
use Keyring\Session\SessionAssurance;
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

        if ($now - $session->lastActivityAt >= 60) {
            $this->sessions->registry()->touch($session->id, $now);
        }

        return $next($request);
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
