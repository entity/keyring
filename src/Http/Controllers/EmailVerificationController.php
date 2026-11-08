<?php

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\EmailVerificationRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;

class EmailVerificationController
{
    use ChoosesFormat;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    public function notice(Request $request): mixed
    {
        return $this->verified($request)
            ? redirect()->intended(config('keyring.home'))
            : $this->keyring->render('verify-email', ['status' => $request->session()->get('status')]);
    }

    public function verify(EmailVerificationRequest $request): mixed
    {
        if (! $this->verified($request)) {
            $request->fulfill();
        }

        return redirect()->intended(config('keyring.home').'?verified=1');
    }

    public function send(Request $request): mixed
    {
        if ($this->verified($request)) {
            return redirect()->intended(config('keyring.home'));
        }

        $request->user()->sendEmailVerificationNotification();

        return $this->wantsJson($request)
            ? new JsonResponse(['status' => 'verification-link-sent'], 202)
            : back()->with('status', 'verification-link-sent');
    }

    protected function verified(Request $request): bool
    {
        $user = $request->user();

        return ! $user instanceof MustVerifyEmail || $user->hasVerifiedEmail();
    }
}
