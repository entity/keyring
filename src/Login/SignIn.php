<?php

namespace Keyring\Login;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Keyring\Activity\SecurityLog;
use Keyring\Devices\DeviceManager;
use Keyring\Enums\Purpose;
use Keyring\Events\Authenticated;
use Keyring\Events\Confirmed;
use Keyring\Events\NewDeviceSignedIn;
use Keyring\KeyringManager;
use Keyring\Models\SecurityEvent;
use Keyring\Session\SessionAssurance;
use Keyring\Sessions\Sessions;

/**
 * The one place a user becomes signed in (after a login or registration)
 * or confirms it's them (step-up). Everything that should happen at those
 * moments happens here.
 */
class SignIn
{
    public function __construct(
        protected KeyringManager $keyring,
        protected SessionAssurance $assurance,
        protected DeviceManager $devices,
        protected Sessions $sessions,
        protected SecurityLog $log,
    ) {}

    public function complete(Request $request, Attempt $attempt): void
    {
        $user = $attempt->user();

        $this->keyring->guard()->login($user, $attempt->remember);
        $request->session()->regenerate();
        $this->assurance->reset($attempt->verifications);

        [$device, $new] = $this->devices->signIn($request, $user, $attempt->trustDevice);
        $this->sessions->start($request, $user, $device, $this->assurance->level());

        Authenticated::dispatch($user, $attempt, $device);

        // "Was this you?" for anything suspicious since they last signed in.
        $request->session()->flash('keyring.alerts', $this->log->alerts($user)->map(fn (SecurityEvent $event) => [
            'type' => $event->type,
            'factor' => $event->factor,
            'at' => $event->created_at->toIso8601String(),
            'ip' => $event->ip,
        ])->all());

        if ($new) {
            NewDeviceSignedIn::dispatch($user, $device);
        }
    }

    public function confirm(Request $request, Attempt $attempt): void
    {
        $request->session()->regenerate();
        $this->assurance->record($attempt->verifications);
        $this->sessions->elevate($request, $this->assurance->level());

        // Keep Laravel's own password.confirm middleware happy too.
        $request->session()->put('auth.password_confirmed_at', now()->getTimestamp());

        Confirmed::dispatch($attempt->user(), $attempt);
    }

    /**
     * Sign in a user who just proved something outside the pipeline, like
     * choosing a password at registration.
     *
     * @param  list<Verification>  $verifications
     */
    public function as(Request $request, Authenticatable&Model $user, array $verifications, bool $remember = false): void
    {
        $this->complete($request, Attempt::start(Purpose::Login, $user, $remember, verifications: $verifications));
    }
}
