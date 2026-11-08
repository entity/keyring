<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Contracts\Auth\PasswordBroker as PasswordBrokerContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\EmailChanges;
use Keyring\Devices\DeviceManager;
use Keyring\Events\PasswordReset;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Notifications\ResetPassword;
use Keyring\Sessions\Sessions;
use Keyring\Support\PasswordRules;

/**
 * Forgotten passwords, the OWASP way: the same answer for every address,
 * links built from APP_URL, no referrer leaks, no automatic sign in, and
 * every session signed out afterwards. Works even while a login is locked.
 */
class PasswordResetController
{
    use ChoosesFormat;

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected DeviceManager $devices,
    ) {}

    public function create(Request $request): mixed
    {
        return $this->keyring->render('forgot-password', ['status' => $request->session()->get('status')]);
    }

    public function store(Request $request): mixed
    {
        $request->validate([$this->keyring->username() => ['required', 'string', 'email', 'max:255']]);

        $email = Str::lower($request->string($this->keyring->username()));

        $this->broker()->sendResetLink([$this->keyring->username() => $email], function (CanResetPassword $user, string $token) {
            Notification::send($user, new ResetPassword($token));
        });

        $status = __('keyring::keyring.reset_link_sent');

        return $this->wantsJson($request) ? new JsonResponse(['status' => $status]) : back()->with('status', $status);
    }

    public function edit(Request $request, string $token): mixed
    {
        $response = $this->keyring->render('reset-password', [
            'token' => $token,
            'email' => (string) $request->query($this->keyring->username()),
        ]);

        $response = Router::toResponse($request, $response);
        $response->headers->set('Referrer-Policy', 'no-referrer');

        return $response;
    }

    public function update(Request $request): mixed
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
            $this->keyring->username() => Str::lower($request->string($this->keyring->username())),
            'token' => $request->input('token'),
            'password' => $request->input('password'),
        ], function ($user, string $password) use ($request) {
            $request->validate(['password' => PasswordRules::for($user instanceof Model && $user instanceof Authenticatable ? $user : null)]);

            $this->keyring->changing(fn () => $user->forceFill([
                'password' => Hash::make($password),
                'remember_token' => Str::random(60),
            ])->save());

            $this->sessions->registry()->revokeAll($user);
            app(EmailChanges::class)->cancel($user);

            PasswordReset::dispatch($user);
        });

        // Laravel says "no user with that address" for unknown accounts. Answer
        // every failure like a bad token instead.
        if ($status !== PasswordBrokerContract::PASSWORD_RESET) {
            throw ValidationException::withMessages([$this->keyring->username() => __(PasswordBrokerContract::INVALID_TOKEN)]);
        }

        return $this->wantsJson($request)
            ? new JsonResponse(['status' => __($status)])
            : redirect()->route('login')->with('status', __($status));
    }

    protected function broker(): PasswordBrokerContract
    {
        return Password::broker(config('keyring.passwords.broker'));
    }
}
