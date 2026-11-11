<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\PasswordBroker;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\ResetsUserPasswords;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Events\LinkRefused;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Support\Input;

use function Illuminate\Support\defer;

/**
 * Forgotten passwords: the same answer for every address,
 * links built from APP_URL, no referrer leaks, no automatic sign in, and
 * every session signed out afterwards. A reset also lifts risk and throttle
 * locks, so a lock can't keep the owner out for good.
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
        Input::validate($request, [$this->keyring->email() => ['required', 'string', 'email', 'max:255']]);

        // After the response, so how long it takes doesn't give away whether
        // the address has an account.
        defer(fn () => $this->broker()->sendResetLink($this->credentials($request)));

        return $this->status('reset-link-sent');
    }

    public function edit(Request $request, #[\SensitiveParameter] string $token): mixed
    {
        return $this->keyring->render('reset-password', [
            'token' => $token,
            'email' => Input::text($request, $this->keyring->email()),
        ]);
    }

    public function update(Request $request, ResetsUserPasswords $resetter): StatusResponse
    {
        // The app's action checks the password rules, which depend on the
        // account (shorter with MFA). They only run once the broker has
        // accepted the token: checking them first would tell anyone whether
        // an address has an account, and MFA.
        $input = Input::validate($request, [
            'token' => ['required', 'string'],
            $this->keyring->email() => ['required', 'string', 'email'],
            'password' => ['required', 'string'],
        ]);

        $status = $this->broker()->reset([
            ...$this->credentials($request),
            ...Arr::only($input, ['token', 'password']),
        ], fn (Authenticatable&Model $user) => $this->passwords->reset(
            $user,
            fn () => $resetter->reset($user, Input::all($request)),
        ));

        // Laravel says "no user with that address" for unknown accounts. Answer
        // every failure like a bad token instead.
        if ($status !== PasswordBroker::PASSWORD_RESET) {
            LinkRefused::dispatch('password_reset', 'token');

            throw ValidationException::withMessages([$this->keyring->email() => __(PasswordBroker::INVALID_TOKEN)]);
        }

        return $this->status('password-reset', redirect: route('login'));
    }

    /**
     * @return array<string, string>
     */
    protected function credentials(Request $request): array
    {
        $email = $this->keyring->email();

        return [$email => $this->keyring->normalizeUsername(Input::text($request, $email))];
    }

    protected function broker(): PasswordBroker
    {
        return Password::broker(config('keyring.passwords.broker'));
    }
}
