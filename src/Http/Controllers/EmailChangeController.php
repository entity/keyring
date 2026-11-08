<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Enums\EmailConfirmation;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Models\PendingChange;

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
    public function store(Request $request): StatusResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
        ]);

        $this->changes->request($request->user(), $validated['email'], $request);

        return $this->status('email-change-requested');
    }

    public function show(Request $request): JsonResponse
    {
        $change = $this->changes->pending($request->user());

        return new JsonResponse(['pending' => $change === null ? null : [
            'email' => $change->value,
            'confirmed' => $change->confirmed_at !== null,
            'needsCurrentConfirmation' => $change->needsCurrentConfirmation(),
            'expiresAt' => $change->expires_at->toIso8601String(),
        ]]);
    }

    public function destroy(Request $request): StatusResponse
    {
        $this->changes->cancel($request->user());

        return $this->status('email-change-cancelled');
    }

    /**
     * The page an emailed link opens. It changes nothing: mail scanners fetch
     * links on their own, so the change only happens when the person presses
     * the button, which POSTs back to the same URL.
     */
    public function page(Request $request, string $change, string $token): mixed
    {
        $change = PendingChange::query()->findOrFail($change);
        $action = $request->routeIs('keyring.email.revert') ? 'revert' : 'confirm';

        return $this->keyring->render('email-change', [
            'action' => $action,
            'url' => route("keyring.email.{$action}.store", ['change' => $change, 'token' => $token]),
        ]);
    }

    /**
     * Confirm from either address. Works signed out, since the link may open
     * in another browser.
     */
    public function confirm(string $change, string $token): StatusResponse
    {
        $change = PendingChange::query()->findOrFail($change);

        $status = match ($this->changes->confirm($change, $token)) {
            EmailConfirmation::Applied => 'email-changed',
            EmailConfirmation::NeedsOtherAddress => 'email-change-confirmed',
            EmailConfirmation::Invalid => 'email-change-invalid',
        };

        return $this->status($status, redirect: $this->keyring->guard()->check() ? config('keyring.home') : route('login'));
    }

    public function revert(string $change, string $token): StatusResponse
    {
        $change = PendingChange::query()->findOrFail($change);

        // Send them to reset their password, when the app has that flow.
        return $this->changes->revert($change, $token)
            ? $this->status('email-change-reverted', redirect: route(Route::has('password.request') ? 'password.request' : 'login'))
            : $this->status('email-change-invalid', redirect: route('login'));
    }
}
