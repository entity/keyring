<?php

namespace Keyring\Http\Controllers;

use Illuminate\Auth\Events\Registered;
use Illuminate\Http\Request;
use Keyring\Contracts\CreatesNewUsers;
use Keyring\Contracts\Responses\RegisterResponse;
use Keyring\Enums\Category;
use Keyring\KeyringManager;
use Keyring\Login\SignIn;
use Keyring\Login\Verification;

class RegisteredUserController
{
    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function create(): mixed
    {
        return $this->keyring->render('register');
    }

    public function store(Request $request, CreatesNewUsers $creator, SignIn $signIn): mixed
    {
        $user = $creator->create($request->all());

        event(new Registered($user));

        // They just chose their password, which counts as knowing it.
        $signIn->as($request, $user, filled($user->getAuthPassword())
            ? [new Verification('password', null, [Category::Knowledge], at: now()->getTimestamp())]
            : []);

        return app(RegisterResponse::class)->toResponse($request);
    }
}
