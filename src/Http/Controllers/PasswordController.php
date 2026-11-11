<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\KeyringManager;
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
     */
    public function update(Request $request, UpdatesUserPasswords $updater, PasswordChanges $passwords, Sessions $sessions): StatusResponse
    {
        $user = $this->keyring->user();

        // Keyring's own field; the rest of the request is the action's.
        $request->validate(['sign_out_others' => ['sometimes', 'boolean']]);

        // The action checks this itself. The published one uses Keyring's
        // CurrentPassword rule; Laravel's current_password goes straight to
        // the hasher, so this covers an action that still uses it.
        $input = Input::all($request);

        if (is_string($input['current_password'] ?? null)) {
            $input['current_password'] = PasswordRules::forVerifying($input['current_password'], $user->getAuthPassword());
        }

        $passwords->change(
            $user,
            fn () => $updater->update($user, $input),
            currentSession: $sessions->current($request)?->id,
            signOutOthers: $request->boolean('sign_out_others', true),
        );

        $sessions->rotate($request);

        return $this->status('password-updated');
    }
}
