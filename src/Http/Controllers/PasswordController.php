<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\Request;
use Keyring\Changes\PasswordChanges;
use Keyring\Contracts\Responses\StatusResponse;
use Keyring\Contracts\UpdatesUserPasswords;
use Keyring\Http\Controllers\Concerns\RespondsWithStatus;
use Keyring\Sessions\Sessions;

class PasswordController
{
    use RespondsWithStatus;

    /**
     * Change the password through the app's UpdatesUserPasswords action.
     */
    public function update(Request $request, UpdatesUserPasswords $updater, PasswordChanges $passwords, Sessions $sessions): StatusResponse
    {
        $user = $request->user();

        // Keyring's own field; the rest of the request is the action's.
        $request->validate(['sign_out_others' => ['sometimes', 'boolean']]);

        $passwords->change(
            $user,
            fn () => $updater->update($user, $request->all()),
            currentSession: $sessions->current($request)?->id,
            signOutOthers: $request->boolean('sign_out_others', true),
        );

        $request->session()->regenerate(true);

        return $this->status('password-updated');
    }
}
