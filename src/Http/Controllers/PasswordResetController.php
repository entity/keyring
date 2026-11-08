<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Support\PasswordRules;
use Symfony\Component\HttpFoundation\Response;

use function Illuminate\Support\defer;

/**
 * Forgotten passwords, the OWASP way: the same answer for every address,
 * links built from APP_URL, no referrer leaks, no automatic sign in, and
 * every session signed out afterwards. A reset also lifts risk locks, so
 * a lock can't keep the owner out for good.
 */
class PasswordResetController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected PasswordChanges $passwords,
    ) {}

    public function create(Request $request): mixed
    {
        return $this->keyring->render('forgot-password', ['status' => $this->statusMessage($request)]);
    }

    public function store(Request $request): StatusResponse
    {
        $request->validate([$this->keyring->username() => ['required', 'string', 'email', 'max:255']]);

        // After the response, so how long it takes doesn't give away whether
        // the address has an account.
        defer(fn () => $this->broker()->sendResetLink([
            $this->keyring->username() => $request->string($this->keyring->username())->lower()->value(),
        ]));

        return $this->status('reset-link-sent');
    }

    public function edit(Request $request, string $token): Response
    {
        $response = Router::toResponse($request, $this->keyring->render('reset-password', [
            'token' => $token,
            'email' => (string) $request->query($this->keyring->username()),
        ]));

        $response->headers->set('Referrer-Policy', 'no-referrer');

        return $response;
    }

    public function update(Request $request): StatusResponse
    {
        // The password rules depend on the account (shorter with MFA), so they
        // only run once the broker has accepted the token. Checking them first
        // would tell anyone whether an address has an account, and MFA.
        $request->validate([
            'token' => ['required', 'string'],
            $this->keyring->username() => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $status = $this->broker()->reset([
            $this->keyring->username() => $request->string($this->keyring->username())->lower()->value(),
            'token' => $request->input('token'),
            'password' => $request->input('password'),
        ], function (Authenticatable&Model $user, string $password) use ($request) {
            $request->validate(['password' => PasswordRules::for($user)]);

            $this->passwords->reset($user, $password);
        });

        // Laravel says "no user with that address" for unknown accounts. Answer
        // every failure like a bad token instead.
        if ($status !== PasswordBroker::PASSWORD_RESET) {
            throw ValidationException::withMessages([$this->keyring->username() => __(PasswordBroker::INVALID_TOKEN)]);
        }

        return $this->status('password-reset', redirect: route('login'));
    }

    protected function broker(): PasswordBroker
    {
        return Password::broker(config('keyring.passwords.broker'));
    }
}
