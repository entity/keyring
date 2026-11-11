<?php

declare(strict_types=1);

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
            ? $this->keyring->response(VerifiedResponse::class)
            : $this->keyring->render('verify-email', ['status' => $this->statusMessage($request)]);
    }

    public function verify(EmailVerificationRequest $request): mixed
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
