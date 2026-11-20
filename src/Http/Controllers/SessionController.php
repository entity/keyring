<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Contracts\Responses\LogoutResponse;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\AccessRefused;
use Keyring\Events\LoggedOut;
use Keyring\Events\SessionsRevoked;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Sessions\Sessions;

/**
 * The user's own sessions, straight from the registry: every one of them,
 * one at a time, whether or not the app keeps devices.
 */
class SessionController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
    ) {}

    public function index(Request $request): JsonResponse
    {
        return new JsonResponse(['sessions' => $this->sessions->list($request, $this->keyring->user())]);
    }

    /**
     * End one session, named by its handle. Ending this one is signing out.
     */
    public function destroy(Request $request, SignIn $signIn, string $session): Responsable
    {
        $user = $this->keyring->user();
        $session = $this->sessions->find($user, $session) ?? $this->refuse($user, $session);

        if ($session->id === $this->sessions->current($request)?->id) {
            $this->sessions->because(SessionEndReason::LoggedOut, fn () => $signIn->out($request));

            LoggedOut::dispatch($user);

            return $this->keyring->response(LogoutResponse::class);
        }

        $this->sessions->revoke($user, $session);

        SessionsRevoked::dispatch($user, 1);

        return $this->status('session-revoked');
    }

    /**
     * A handle that isn't one of the user's own sessions: someone else's, or
     * one that has ended. Either way it's the 404 a missing one gets, and
     * the attempt goes on record.
     */
    protected function refuse(Authenticatable $user, string $handle): never
    {
        AccessRefused::dispatch($user, 'session', $handle);

        abort(404);
    }

    /**
     * Sign out everywhere except here.
     */
    public function destroyOthers(Request $request): StatusResponse
    {
        $this->sessions->signOutOthers($request, $this->keyring->user());

        return $this->status('sessions-revoked');
    }
}
