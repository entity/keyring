<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\DiscoverableFactor;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Contracts\Responses\LogoutResponse;
use Keyring\Enums\Purpose;
use Keyring\Events\LoggedOut;
use Keyring\Http\Controllers\Concerns\RespondsToVerification;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Pipeline\Context;
use Keyring\Session\SessionAssurance;
use Keyring\Sessions\Sessions;

class AuthenticatedSessionController
{
    use RespondsToVerification;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function create(Request $request): mixed
    {
        return $this->keyring->render('login', [
            'canResetPassword' => Route::has('password.request'),
            'status' => $request->session()->get('status'),
        ]);
    }

    /**
     * Options for a usernameless sign in, e.g. GET /login/passkey/options.
     */
    public function options(Request $request, string $factor): JsonResponse
    {
        $factor = $this->keyring->hasFactor($factor) ? $this->keyring->factor($factor) : abort(404);

        abort_unless($factor instanceof DiscoverableFactor, 404);

        return new JsonResponse($factor->loginOptions($request));
    }

    /**
     * Start a login with a primary factor (the password by default).
     */
    public function store(Request $request, AttemptStore $attempts, string $factor = 'password'): mixed
    {
        $factor = $this->keyring->hasFactor($factor) ? $this->keyring->factor($factor) : abort(404);

        abort_unless($factor instanceof PrimaryFactor, 404);

        $attempts->forget(Purpose::Login);

        return $this->verifyAndRespond(new Context($request, Purpose::Login, $factor));
    }

    public function destroy(Request $request, SessionAssurance $assurance, Sessions $sessions): mixed
    {
        $user = $this->keyring->guard()->user();

        $sessions->end($request);
        $this->keyring->guard()->logout();
        $assurance->flush();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        if ($user !== null) {
            LoggedOut::dispatch($user);
        }

        return app(LogoutResponse::class)->toResponse($request);
    }
}
