<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\DiscoverableFactor;
use Keyring\Contracts\Responses\LogoutResponse;
use Keyring\Events\LoggedOut;
use Keyring\Factors\Password;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;

class AuthenticatedSessionController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function create(Request $request): mixed
    {
        return $this->keyring->render('login', [
            'canResetPassword' => Route::has('password.request'),
            'canRegister' => Route::has('register'),
            'status' => $this->statusMessage($request),
        ]);
    }

    /**
     * Options for a usernameless sign in, e.g. GET /login/passkey/options.
     */
    public function options(Request $request, string $factor): JsonResponse
    {
        $factor = $this->keyring->factor($factor);

        abort_unless($factor instanceof DiscoverableFactor && $factor->startsLogin(), 404);

        return new JsonResponse($factor->loginOptions($request));
    }

    /**
     * Start a login with a primary factor (the password by default).
     */
    public function store(Request $request, string $factor = Password::KEY): mixed
    {
        return $this->keyring->attempt($request, $factor);
    }

    public function destroy(Request $request, SignIn $signIn): mixed
    {
        if ($user = $signIn->out($request)) {
            LoggedOut::dispatch($user);
        }

        return $this->keyring->response(LogoutResponse::class)->toResponse($request);
    }
}
