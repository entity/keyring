<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\DiscoverableFactor;
use Keyring\Contracts\Responses\LogoutResponse;
use Keyring\Enums\SessionEndReason;
use Keyring\Events\LoggedOut;
use Keyring\Factors\Password;
use Keyring\Factors\SingleSignOn;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Sessions\Sessions;

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
            'providers' => $this->providers(),
        ]);
    }

    /**
     * The identity providers to offer buttons for, once the SingleSignOn
     * factor is registered: each one's name, label and where it sends the
     * user to sign in.
     *
     * @return list<array{name: string, label: string, url: string}>
     */
    protected function providers(): array
    {
        $factor = $this->keyring->hasFactor(SingleSignOn::KEY) ? $this->keyring->factor(SingleSignOn::KEY) : null;

        return $factor instanceof SingleSignOn ? $factor->providers() : [];
    }

    /**
     * Options for a usernameless sign in, e.g. GET /login/passkey/options.
     * Under "options", as a challenge and an enrollment send theirs, which is
     * also where Laravel's passkeys client reads them.
     */
    public function options(Request $request, string $factor): JsonResponse
    {
        $factor = $this->keyring->factor($factor);

        abort_unless($factor instanceof DiscoverableFactor && $factor->startsLogin(), 404);

        return new JsonResponse(['options' => $factor->loginOptions($request)]);
    }

    /**
     * Start a login with a primary factor (the password by default).
     */
    public function store(Request $request, string $factor = Password::KEY): mixed
    {
        return $this->keyring->attempt($request, $factor);
    }

    public function destroy(Request $request, SignIn $signIn, Sessions $sessions): mixed
    {
        if ($user = $sessions->because(SessionEndReason::LoggedOut, fn () => $signIn->out($request))) {
            LoggedOut::dispatch($user);
        }

        return $this->keyring->response(LogoutResponse::class)->toResponse($request);
    }
}
