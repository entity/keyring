<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\ValidatesEmailChanges;
use Keyring\Enums\EmailConfirmation;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Support\Input;
use Keyring\Support\Throttle;
use Keyring\Support\Url;

class EmailChangeController
{
    use RespondsWithStatus;

    public function __construct(
        protected EmailChanges $changes,
        protected KeyringManager $keyring,
    ) {}

    /**
     * Ask to change the email. Always answers the same way, whether or not
     * the address belongs to someone else.
     */
    public function store(Request $request, ValidatesEmailChanges $validator, Throttle $throttle): StatusResponse
    {
        $user = $this->keyring->user();

        // A change waits for the current address to confirm, and one nobody
        // has verified never has. Asking would only send mail, to whoever
        // was typed at registration and whoever is typed now.
        if ($user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()) {
            throw ValidationException::withMessages([$this->keyring->email() => __('keyring::keyring.verify_email_to_change')]);
        }

        $email = $validator->validate($user, $request->all());

        // Every request mails two addresses, so they're counted like the
        // notices they are, not just by the form's own limit.
        if (($wait = $throttle->notifying('email_change', $user::class.':'.$user->getAuthIdentifier())) !== null) {
            throw Throttle::exception($this->keyring->email(), $wait);
        }

        $this->changes->request($user, $email, $request);

        return $this->status('email-change-requested');
    }

    public function show(Request $request): JsonResponse
    {
        $change = $this->changes->pending($this->keyring->user());

        return new JsonResponse(['pending' => $change === null ? null : [
            'email' => $change->value,
            'confirmed' => $change->confirmed_at !== null,
            'needsCurrentConfirmation' => $change->needsCurrentConfirmation(),
            'expiresAt' => $change->expires_at->toIso8601String(),
        ]]);
    }

    public function destroy(Request $request): StatusResponse
    {
        $this->changes->cancel($this->keyring->user());

        return $this->status('email-change-cancelled');
    }

    /**
     * The page an emailed link opens. It changes nothing: mail scanners fetch
     * links on their own, so the change only happens when the person presses
     * the button. That posts the link's token in the body, to a URL without
     * it: the link had to carry it in the URL, the request that acts doesn't.
     */
    public function page(Request $request, string $change, #[\SensitiveParameter] string $token): mixed
    {
        $change = $this->keyring->pendingChangeModel()::query()->findOrFail($change);
        $action = $request->routeIs('keyring.email.revert') ? 'revert' : 'confirm';

        return $this->keyring->render('email-change', [
            'action' => $action,
            'url' => Url::route("keyring.email.{$action}.store", ['change' => $change]),
            'token' => $token,
        ]);
    }

    /**
     * Confirm from either address. Works signed out, since the link may open
     * in another browser.
     */
    public function confirm(Request $request, string $change): StatusResponse
    {
        $change = $this->changes->fromLink($change, 'email_change_confirm');

        $status = match ($this->changes->confirm($change, Input::text($request, 'token'))) {
            EmailConfirmation::Applied => 'email-changed',
            EmailConfirmation::NeedsOtherAddress => 'email-change-confirmed',
            EmailConfirmation::Invalid => 'email-change-invalid',
        };

        return $this->status($status, redirect: $this->keyring->guard()->check() ? config('keyring.home') : route('login'));
    }

    public function revert(Request $request, string $change): StatusResponse
    {
        $change = $this->changes->fromLink($change, 'email_change_revert');

        // Send them to reset their password, when the app has that flow.
        return $this->changes->revert($change, Input::text($request, 'token'))
            ? $this->status('email-change-reverted', redirect: route(Route::has('password.request') ? 'password.request' : 'login'))
            : $this->status('email-change-invalid', redirect: route('login'));
    }
}
