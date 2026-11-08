<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Sessions\Sessions;
use Keyring\Support\PasswordRules;

class PasswordController
{
    use RespondsWithStatus;

    /**
     * Change the password. Users who have one must type it (OWASP: covers a
     * session left open on a shared computer); passwordless users rely on the
     * fresh verification the route already requires.
     */
    public function update(Request $request, PasswordChanges $passwords, Sessions $sessions): StatusResponse
    {
        $user = $request->user();

        $validated = $request->validate([
            'current_password' => filled($user->getAuthPassword())
                ? ['required', 'string', 'current_password:'.config('keyring.guard')]
                : ['nullable'],
            'password' => PasswordRules::for($user),
            'sign_out_others' => ['sometimes', 'boolean'],
        ]);

        $passwords->change(
            $user,
            $validated['password'],
            currentSession: $sessions->current($request)?->id,
            signOutOthers: $validated['sign_out_others'] ?? true,
        );

        $request->session()->regenerate();

        return $this->status('password-updated');
    }
}
