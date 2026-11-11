<?php

namespace Keyring\Http\Controllers;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\Events\Registered;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Contracts\CreatesNewUsers;
use Keyring\Contracts\Responses\RegisterResponse;
use Keyring\Enums\Category;
use Keyring\Exceptions\EmailVerificationRequired;
use Keyring\Factors\Password;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;
use Keyring\Support\Input;

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

    public function store(Request $request, CreatesNewUsers $creator, SignIn $signIn): mixed
    {
        // Before anything is saved, so a broken setup doesn't take the address.
        $provider = $this->keyring->provider();

        if ($provider instanceof EloquentUserProvider && is_a($provider->getModel(), MustVerifyEmail::class, true)) {
            throw_unless(Route::has('verification.verify'), EmailVerificationRequired::forRegistration($provider->getModel()));
        }

        $user = $creator->create(Input::all($request));

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
