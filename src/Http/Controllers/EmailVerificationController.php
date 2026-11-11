<?php

namespace Keyring\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Keyring\Contracts\Responses\VerifiedResponse;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Http\Requests\VerifyEmailRequest;
use Keyring\KeyringManager;
use Keyring\Login\VerificationLink;

class EmailVerificationController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function notice(Request $request): mixed
    {
        return $this->verified($request)
            ? $this->keyring->response(VerifiedResponse::class)
            : $this->keyring->render('verify-email', ['status' => $this->statusMessage($request)]);
    }

    /**
     * The emailed link, which the route has checked the signature of. A
     * browser that isn't signed in is sent to sign in and comes back, as
     * the auth middleware would send it. Where registration hides who has
     * an account, the link is what lets an unverified user sign in at all.
     */
    public function verify(Request $request, VerificationLink $link, string $id, string $hash): mixed
    {
        if ($this->keyring->guard()->guest()) {
            if ($this->keyring->hidesRegisteredAddresses()) {
                $link->remember($request, $id, $hash);
                $request->session()->flash('status', 'sign-in-to-verify');
            }

            throw new AuthenticationException(guards: [config('keyring.guard')], redirectTo: route('login'));
        }

        // As the auth middleware does, so the request's user is Keyring's.
        Auth::shouldUse(config('keyring.guard'));

        // Laravel's check that the link is this user's own, made now that
        // there is a user to check it against.
        $verification = app(VerifyEmailRequest::class);

        if (! $this->verified($request)) {
            $verification->fulfill();
        }

        return $this->keyring->response(VerifiedResponse::class, justNow: true);
    }

    public function send(Request $request): mixed
    {
        if ($this->verified($request)) {
            return $this->keyring->response(VerifiedResponse::class);
        }

        $user = $this->keyring->user();

        if ($user instanceof MustVerifyEmail) {
            $user->sendEmailVerificationNotification();
        }

        return $this->status('verification-link-sent');
    }

    protected function verified(Request $request): bool
    {
        $user = $this->keyring->user();

        return ! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail();
    }
}
