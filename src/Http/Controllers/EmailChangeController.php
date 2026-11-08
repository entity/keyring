<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Keyring\Changes\EmailChanges;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Models\PendingChange;

class EmailChangeController
{
    use ChoosesFormat;

    public function __construct(
        protected EmailChanges $changes,
        protected KeyringManager $keyring,
    ) {}

    /**
     * Ask to change the email. Always answers the same way, whether or not
     * the address belongs to someone else.
     */
    public function store(Request $request): mixed
    {
        $validated = $request->validate([
            'email' => ['required', 'string', 'email', 'max:255'],
        ]);

        $this->changes->request($request->user(), $validated['email']);

        return $this->respond($request, 'email-change-requested');
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

    public function destroy(Request $request): mixed
    {
        $this->changes->cancel($request->user());

        return $this->respond($request, 'email-change-cancelled');
    }

    /**
     * The page an emailed link opens. It changes nothing: mail scanners fetch
     * links on their own, so the change only happens when the person presses
     * the button, which POSTs back to the same URL.
     */
    public function page(Request $request, string $change, string $token): mixed
    {
        PendingChange::query()->findOrFail($change);
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
    public function confirm(string $change, string $token): mixed
    {
        $change = PendingChange::query()->findOrFail($change);
        $applied = $this->changes->confirm($change, $token);
        $change = $change->fresh();

        $status = match (true) {
            $applied => 'email-changed',
            $change?->isPending() === true && $this->changes->recognises($change, $token) => 'email-change-confirmed',
            default => 'email-change-invalid',
        };

        return redirect($this->keyring->guard()->check() ? config('keyring.home') : route('login'))->with('status', $status);
    }

    public function revert(string $change, string $token): mixed
    {
        $change = PendingChange::query()->findOrFail($change);
        $reverted = $this->changes->revert($change, $token);

        // Send them to reset their password, when the app has that flow.
        return redirect()->route($reverted && Route::has('password.request') ? 'password.request' : 'login')
            ->with('status', $reverted ? 'email-change-reverted' : 'email-change-invalid');
    }

    protected function respond(Request $request, string $status): mixed
    {
        return $this->wantsJson($request) ? new JsonResponse(['status' => $status]) : back()->with('status', $status);
    }
}
