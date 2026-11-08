<?php

namespace Keyring\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Keyring\Devices\DeviceManager;
use Keyring\Events\PasswordChanged;
use Keyring\Http\Responses\ChoosesFormat;
use Keyring\KeyringManager;
use Keyring\Sessions\Sessions;
use Keyring\Support\PasswordRules;

class PasswordController
{
    use ChoosesFormat;

    public function __construct(
        protected KeyringManager $keyring,
        protected Sessions $sessions,
        protected DeviceManager $devices,
    ) {}

    /**
     * Change the password. Users who have one must type it (OWASP: covers a
     * session left open on a shared computer); passwordless users rely on the
     * fresh verification the route already requires.
     */
    public function update(Request $request): mixed
    {
        $user = $request->user();
        $hasPassword = filled($user->getAuthPassword());

        $validated = $request->validate([
            'current_password' => $hasPassword ? ['required', 'string'] : ['nullable'],
            'password' => PasswordRules::for($user),
            'sign_out_others' => ['sometimes', 'boolean'],
        ]);

        if ($hasPassword && ! Hash::check($validated['current_password'], $user->getAuthPassword())) {
            throw ValidationException::withMessages(['current_password' => __('auth.password')]);
        }

        $this->keyring->changing(fn () => $user->forceFill(['password' => Hash::make($validated['password'])])->save());

        $request->session()->regenerate();

        if ($validated['sign_out_others'] ?? true) {
            $this->sessions->registry()->revokeAll($user, except: $this->sessions->current($request)?->id);
            $this->devices->cycleRememberToken($user);
        }

        PasswordChanged::dispatch($user);

        return $this->wantsJson($request)
            ? new JsonResponse(['status' => 'password-updated'])
            : back()->with('status', 'password-updated');
    }
}
