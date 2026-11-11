<?php

declare(strict_types=1);

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Validation\Rule;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
use Keyring\Rules\CurrentPassword;
use Keyring\Sessions\Sessions;
use Keyring\Support\Input;
use Keyring\Support\PasswordRules;

class PasswordController
{
    use RespondsWithStatus;

    public function __construct(
        protected KeyringManager $keyring,
    ) {}

    /**
     * Change the password through the app's UpdatesUserPasswords action.
     * Keyring asks for the current password itself, so that doesn't rest on
     * what the app's action checks: a fresh verification can be a passkey,
     * and a session left open on a shared computer has one too.
     */
    public function update(Request $request, UpdatesUserPasswords $updater, PasswordChanges $passwords, Sessions $sessions): StatusResponse
    {
        $user = $this->keyring->user();

        // Keyring's own fields; the rest of the request is the action's.
        // Users who only sign in with passkeys have no password to type.
        Input::validate($request, [
            'sign_out_others' => ['sometimes', 'boolean'],
            'current_password' => Rule::when(filled($user->getAuthPassword()), ['required', 'string', new CurrentPassword($user)]),
        ]);

        $passwords->change(
            $user,
            fn () => $updater->update($user, PasswordRules::normalizeInput(Input::all($request))),
            currentSession: $sessions->current($request)?->id,
            signOutOthers: $request->boolean('sign_out_others', true),
            current: is_string($current = $request->input('current_password')) ? $current : null,
        );

        $sessions->rotate($request);

        return $this->status('password-updated');
    }
}
