<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\Request;
use Keyring\Contracts\Responses\VerifiedResponse;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;

class EmailVerificationController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function notice(Request $request): mixed
    {
        return $this->verified($request)
            ? app(VerifiedResponse::class)
            : $this->keyring->render('verify-email', ['status' => $this->statusMessage($request)]);
    }

    public function verify(EmailVerificationRequest $request): mixed
    {
        if (! $this->verified($request)) {
            $request->fulfill();
        }

        return app(VerifiedResponse::class, ['justNow' => true]);
    }

    public function send(Request $request): mixed
    {
        if ($this->verified($request)) {
            return app(VerifiedResponse::class);
        }

        $request->user()->sendEmailVerificationNotification();

        return $this->status('verification-link-sent');
    }

    protected function verified(Request $request): bool
    {
        $user = $request->user();

        return ! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail();
    }
}
