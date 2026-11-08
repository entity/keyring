<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Keyring\Changes\EmailChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Events\PasswordChanged;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Sessions\Sessions;
use Keyring\Support\PasswordRules;

class PasswordController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected EmailChanges $emailChanges,
    ) {}

    /**
     * Change the password. Users who have one must type it (OWASP: covers a
     * session left open on a shared computer); passwordless users rely on the
     * fresh verification the route already requires.
     */
    public function update(Request $request): StatusResponse
    {
        $user = $request->user();

        $validated = $request->validate([
            'current_password' => filled($user->getAuthPassword())
                ? ['required', 'string', 'current_password:'.config('keyring.guard')]
                : ['nullable'],
            'password' => PasswordRules::for($user),
            'sign_out_others' => ['sometimes', 'boolean'],
        ]);

        $this->keyring->changing(fn () => $user->forceFill(['password' => Hash::make($validated['password'])])->save());

        $request->session()->regenerate();

        // Whoever might know the old password shouldn't keep a change of
        // address they started with it.
        $this->emailChanges->cancel($user);

        if ($validated['sign_out_others'] ?? true) {
            $this->sessions->revokeAll($user, except: $this->sessions->current($request)?->id);
        }

        PasswordChanged::dispatch($user);

        return $this->status('password-updated');
    }
}
