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
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Login\SignIn;
use Keyring\Pipeline\Context;

class AuthenticatedSessionController
{
    use RespondsToVerification, RespondsWithStatus;

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
    public function store(Request $request, AttemptStore $attempts, string $factor = 'password'): mixed
    {
        $factor = $this->keyring->factor($factor);

        abort_unless($factor instanceof PrimaryFactor && $factor->startsLogin(), 404);

        $attempts->forget(Purpose::Login);

        return $this->verifyAndRespond(new Context($request, Purpose::Login, $factor));
    }

    public function destroy(Request $request, SignIn $signIn): mixed
    {
        if ($user = $signIn->out($request)) {
            LoggedOut::dispatch($user);
        }

        return app(LogoutResponse::class)->toResponse($request);
    }
}
