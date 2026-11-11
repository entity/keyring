<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Keyring\Contracts\Responses\VerifiedResponse;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Http\Requests\VerifyEmailRequest;
use Keyring\KeyringManager;
use Keyring\Login\VerificationLink;
use Keyring\Support\Input;
use Keyring\Support\Throttle;

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
     * The page the emailed link opens. It verifies nothing: a GET changes
     * nothing in Keyring, and whatever opens the link before the person
     * does (a mail scanner, a browser loading it ahead) shouldn't be what
     * verifies the address. The page's button posts the link's signature
     * in the body (ValidatePostedSignature).
     *
     * A browser that isn't signed in is sent to sign in and comes back, as
     * the auth middleware would send it. Where registration hides who has
     * an account, having followed the link is what lets an unverified user
     * sign in at all, and signing in is what verifies their address.
     */
    public function page(Request $request, VerificationLink $link, string $id, string $hash): mixed
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
        $request = app(VerifyEmailRequest::class);
        $user = $this->keyring->user();

        if (! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail()) {
            return $this->keyring->response(VerifiedResponse::class);
        }

        return $this->keyring->render('email-verification', [
            'email' => $user->getEmailForVerification(),
            'url' => Str::before($request->getRequestUri(), '?'),
            'expires' => Input::text($request, 'expires'),
            'signature' => Input::text($request, 'signature'),
        ]);
    }

    public function verify(VerifyEmailRequest $request): mixed
    {
        if (! $this->verified($request)) {
            $request->fulfill();
        }

        return $this->keyring->response(VerifiedResponse::class, justNow: true);
    }

    public function send(Request $request, Throttle $throttle): mixed
    {
        if ($this->verified($request)) {
            return $this->keyring->response(VerifiedResponse::class);
        }

        $user = $this->keyring->user();

        if ($user instanceof MustVerifyEmail) {
            // The address is whatever was typed at registration, and nobody
            // has shown it's theirs. It's mailed no more often from here
            // than from the registration form, and out of the same count.
            // The account is its own, so it's told when that's used up.
            $address = $this->keyring->normalizeUsername($user->getEmailForVerification());

            if (($wait = $throttle->notifying('registration', 'mail:'.$address)) !== null) {
                throw Throttle::exception($this->keyring->email(), $wait);
            }

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
