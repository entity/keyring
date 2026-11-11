<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Keyring\Contracts\CreatesNewUsers;
use Keyring\Contracts\Responses\RegisterResponse;
use Keyring\Enums\Category;
use Keyring\Factors\Password;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\Registration;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;
use Keyring\Support\Throttle;

class RegisteredUserController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function create(): mixed
    {
        return $this->keyring->render('register');
    }

    public function store(Request $request, CreatesNewUsers $creator, Registration $registration, SignIn $signIn, Throttle $throttle): mixed
    {
        // Before anything is saved, so a broken setup doesn't take the address.
        $registration->ensureReady();

        // The same answer whether the address was free or not. Nobody is
        // signed in: only a new account could be, and that would show.
        if ($this->keyring->hidesRegisteredAddresses()) {
            $registration->quietly($request, $creator);

            return $this->status('registration-received', redirect: route('login'));
        }

        $user = $registration->openly($request, $creator);

        // Laravel's listener mails the verification link. Counted with what
        // the address is sent if a new one is asked for.
        if ($user instanceof MustVerifyEmail) {
            $throttle->notifying('registration', 'mail:'.$this->keyring->normalizeUsername($user->getEmailForVerification()));
        }

        event(new Registered($user));

        if (! $this->keyring->signsInAfterRegistering($user, $request)) {
            return $this->status('registered', redirect: route('login'));
        }

        // They just chose their password, which counts as knowing it.
        $signIn->as($request, $user, filled($user->getAuthPassword())
            ? [new Verification(Password::KEY, null, [Category::Knowledge], at: now()->getTimestamp())]
            : []);

        return $this->keyring->response(RegisterResponse::class)->toResponse($request);
    }
}
