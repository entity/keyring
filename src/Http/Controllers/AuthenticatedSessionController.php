<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\PrimaryFactor;
use Keyring\Contracts\Responses\LogoutResponse;
use Keyring\Enums\Purpose;
use Keyring\Events\LoggedOut;
use Keyring\Http\Controllers\Concerns\RespondsToVerification;
use Keyring\KeyringManager;
use Keyring\Login\AttemptStore;
use Keyring\Pipeline\Context;
use Keyring\Session\SessionAssurance;

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
     * Start a login with a primary factor (the password by default).
     */
    public function store(Request $request, AttemptStore $attempts, string $factor = 'password'): mixed
    {
        $factor = $this->keyring->hasFactor($factor) ? $this->keyring->factor($factor) : abort(404);

        abort_unless($factor instanceof PrimaryFactor, 404);

        $attempts->forget(Purpose::Login);

        return $this->verifyAndRespond(new Context($request, Purpose::Login, $factor));
    }

    public function destroy(Request $request, SessionAssurance $assurance): mixed
    {
        $user = $this->keyring->guard()->user();

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
