<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Keyring\Contracts\Responses\VerifiedResponse;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Http\Requests\VerifyEmailRequest;
use Keyring\KeyringManager;
use Keyring\Support\Input;

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
     */
    public function page(VerifyEmailRequest $request): mixed
    {
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
